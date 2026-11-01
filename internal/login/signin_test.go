package login

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yokonao/saml2sts/internal/config"
	"github.com/yokonao/saml2sts/internal/federation"
	"github.com/yokonao/saml2sts/internal/store"
)

type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// answer waits for the previous result to be consumed, then writes r.
func answer(t *testing.T, r store.Result) {
	t.Helper()
	for res, _ := store.ReadResult(); res != nil; res, _ = store.ReadResult() {
		time.Sleep(50 * time.Millisecond)
	}
	if err := store.WriteResult(r); err != nil {
		t.Error(err)
	}
}

// TestSignInChecksTheSecret plays the host: a result with another secret and
// an error must not end the login, and the matching result must.
func TestSignInChecksTheSecret(t *testing.T) {
	restore := store.UseService(fmt.Sprintf("saml2sts.test.%d.%s", os.Getpid(), t.Name()))
	t.Cleanup(func() {
		_ = store.DeletePending()
		_ = store.DeleteResult()
		restore()
	})
	cfg := config.Config{IDP: config.IDP{URL: "https://idp.example.com/sso"}}
	var log syncBuffer
	creds := &federation.Credentials{AccessKeyID: "AKID", Expiration: time.Now().Add(time.Hour)}
	const role = "arn:aws:iam::111111111111:role/admin"

	go func() {
		var p *store.Pending
		for p == nil {
			time.Sleep(50 * time.Millisecond)
			p, _ = store.ReadPending()
		}
		answer(t, store.Result{Secret: "WRONG", Credentials: creds, RoleARN: role})
		answer(t, store.Result{Secret: p.Secret, Error: "bad assertion"})
		answer(t, store.Result{Secret: p.Secret, Credentials: creds, RoleARN: role})
	}()
	r, err := signIn(context.Background(), cfg, store.Pending{RoleARN: role},
		Options{NoOpen: true, Timeout: 20 * time.Second, Log: &log})
	if err != nil {
		t.Fatal(err)
	}
	if r.Credentials == nil || r.Credentials.AccessKeyID != "AKID" {
		t.Errorf("result = %+v", r)
	}
	for _, want := range []string{"#saml2sts=", "ignoring a result that does not match", "bad assertion; still waiting"} {
		if !strings.Contains(log.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, log.String())
		}
	}
	if p, _ := store.ReadPending(); p != nil {
		t.Error("signIn left the pending login behind")
	}
}
