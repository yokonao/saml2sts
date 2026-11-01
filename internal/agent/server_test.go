package agent

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yokonao/saml2sts/internal/federation"
)

// listen serves handle on a new socket until the test ends.
func listen(t *testing.T, handle Handler) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "agent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, l, handle) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve = %v", err)
		}
	})
	return sock
}

func TestServe(t *testing.T) {
	sock := listen(t, func(_ context.Context, req Request) Response {
		if req.Method == MethodRoles {
			return Response{Roles: []Role{{ARN: "arn:aws:iam::1:role/dev"}}}
		}
		return Response{Credentials: &federation.Credentials{AccessKeyID: "AKIA"}, RoleARN: "arn:aws:iam::1:role/" + req.Role}
	})
	c, arn, err := Credentials(context.Background(), sock, "dev")
	if err != nil || c.AccessKeyID != "AKIA" || arn != "arn:aws:iam::1:role/dev" {
		t.Errorf("Credentials = %+v, %s, %v", c, arn, err)
	}
	if roles, err := Roles(context.Background(), sock); err != nil || len(roles) != 1 {
		t.Errorf("Roles = %v, %v", roles, err)
	}
}

func TestServeRejects(t *testing.T) {
	sock := listen(t, func(context.Context, Request) Response {
		t.Error("handler called")
		return Response{}
	})
	for line, want := range map[string]string{
		"not json\n":                             "malformed",
		`{"version":99,"method":"roles"}` + "\n": "protocol version 1",
	} {
		conn, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
		var r Response
		if err := json.NewDecoder(conn).Decode(&r); err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		if r.Version != Version || !strings.Contains(r.Error, want) {
			t.Errorf("%q: got %+v, want %q", line, r, want)
		}
	}
}

func TestServeCancelsOnHangUp(t *testing.T) {
	canceled := make(chan struct{})
	sock := listen(t, func(ctx context.Context, _ Request) Response {
		select {
		case <-ctx.Done():
			close(canceled)
		case <-time.After(5 * time.Second):
		}
		return Response{}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, _ = Call(ctx, sock, Request{Method: MethodRoles})
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Error("the handler went on after the client hung up")
	}
}
