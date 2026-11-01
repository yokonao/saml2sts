package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yokonao/saml2sts/internal/nativemsg"
	"github.com/yokonao/saml2sts/internal/saml"
	"github.com/yokonao/saml2sts/internal/store"
)

const (
	adminARN    = "arn:aws:iam::111111111111:role/admin"
	readonlyARN = "arn:aws:iam::111111111111:role/readonly"
	providerARN = "arn:aws:iam::111111111111:saml-provider/idp"
)

// useTestStore points the store at Keychain items of this test only.
func useTestStore(t *testing.T) {
	t.Helper()
	restore := store.UseService(fmt.Sprintf("saml2sts.test.%d.%s", os.Getpid(), t.Name()))
	t.Cleanup(func() {
		_ = store.DeletePending()
		_ = store.DeleteResult()
		_ = store.DeleteChoice()
		_ = store.Forget()
		restore()
	})
}

type stsCalls struct {
	mu        sync.Mutex
	roles     []string
	durations []string
}

func (c *stsCalls) get() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.roles)
}

func (c *stsCalls) getDurations() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.durations)
}

// fakeSTS answers AssumeRoleWithSAML, with an error when fail is set, and
// records the role each call asked for.
func fakeSTS(t *testing.T, fail bool) *stsCalls {
	t.Helper()
	return fakeSTSWith(t, fail, 0, "")
}

// fakeSTSWith also rejects durations above maxSeconds, when not zero, and
// appends roles to the [roles] of the config.
func fakeSTSWith(t *testing.T, fail bool, maxSeconds int, roles string) *stsCalls {
	t.Helper()
	calls := &stsCalls{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		calls.mu.Lock()
		calls.roles = append(calls.roles, r.Form.Get("RoleArn"))
		calls.durations = append(calls.durations, r.Form.Get("DurationSeconds"))
		calls.mu.Unlock()
		w.Header().Set("Content-Type", "text/xml")
		if d, _ := strconv.Atoi(r.Form.Get("DurationSeconds")); maxSeconds > 0 && d > maxSeconds {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, `<ErrorResponse><Error><Type>Sender</Type><Code>ValidationError</Code><Message>The requested DurationSeconds exceeds the MaxSessionDuration set for this role.</Message></Error></ErrorResponse>`)
			return
		}
		if fail {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, `<ErrorResponse><Error><Type>Sender</Type><Code>InvalidIdentityToken</Code><Message>bad assertion</Message></Error></ErrorResponse>`)
			return
		}
		_, _ = fmt.Fprint(w, `<AssumeRoleWithSAMLResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithSAMLResult><Credentials>`+
			`<AccessKeyId>AKID</AccessKeyId><SecretAccessKey>SECRET</SecretAccessKey><SessionToken>TOKEN</SessionToken>`+
			`<Expiration>2030-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleWithSAMLResult></AssumeRoleWithSAMLResponse>`)
	}))
	t.Cleanup(srv.Close)
	cfg := filepath.Join(t.TempDir(), "config.toml")
	body := fmt.Sprintf("[idp]\nurl = \"https://idp.example.com/sso\"\nsts_endpoint = %q\n\n[roles]\nprod-admin = %q\n%s", srv.URL, adminARN, roles)
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAML2STS_CONFIG", cfg)
	return calls
}

func samlResponse(roleARNs ...string) string {
	var b strings.Builder
	b.WriteString(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion><saml:AttributeStatement><saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">`)
	for _, arn := range roleARNs {
		fmt.Fprintf(&b, "<saml:AttributeValue>%s,%s</saml:AttributeValue>", arn, providerARN)
	}
	b.WriteString(`</saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>`)
	return base64.StdEncoding.EncodeToString([]byte(b.String()))
}

// host runs the native host on one request and returns its replies.
func host(t *testing.T, req hostRequest) []hostReply {
	t.Helper()
	var in, out bytes.Buffer
	if err := nativemsg.Write(&in, req); err != nil {
		t.Fatal(err)
	}
	if err := runNativeHost(&in, &out); err != nil {
		t.Fatal(err)
	}
	var replies []hostReply
	for out.Len() > 0 {
		var r hostReply
		if err := nativemsg.Read(&out, &r); err != nil {
			t.Fatal(err)
		}
		replies = append(replies, r)
	}
	return replies
}

func writePending(t *testing.T, p store.Pending) store.Pending {
	t.Helper()
	p.Secret, p.Nonce, p.Expires = "SECRET", "NONCE", time.Now().Add(time.Minute)
	if err := store.WritePending(p); err != nil {
		t.Fatal(err)
	}
	return p
}

func statuses(replies []hostReply) string {
	b, _ := json.Marshal(replies)
	return string(b)
}

func TestNativeHostIdle(t *testing.T) {
	useTestStore(t)
	calls := fakeSTS(t, false)
	if r := host(t, hostRequest{SAMLResponse: samlResponse(adminARN), Nonce: "NONCE"}); len(r) != 1 || r[0].Status != "idle" {
		t.Errorf("without a pending login: %s", statuses(r))
	}
	writePending(t, store.Pending{RoleARN: adminARN})
	for _, nonce := range []string{"", "OTHER"} {
		if r := host(t, hostRequest{SAMLResponse: samlResponse(adminARN), Nonce: nonce}); len(r) != 1 || r[0].Status != "idle" {
			t.Errorf("nonce %q: %s", nonce, statuses(r))
		}
	}
	if p, _ := store.ReadPending(); p == nil {
		t.Error("an ignored response ended the pending login")
	}
	if len(calls.get()) != 0 {
		t.Errorf("STS called for %v", calls.get())
	}
}

func TestNativeHostExchange(t *testing.T) {
	useTestStore(t)
	calls := fakeSTS(t, false)
	writePending(t, store.Pending{RoleARN: adminARN})
	r := host(t, hostRequest{SAMLResponse: samlResponse(adminARN, readonlyARN), Nonce: "NONCE"})
	if len(r) != 1 || r[0].Status != "ok" || r[0].Role != "prod-admin" {
		t.Fatalf("replies = %s", statuses(r))
	}
	if !slices.Equal(calls.get(), []string{adminARN}) {
		t.Errorf("STS calls = %v", calls.get())
	}
	res, err := store.ReadResult()
	if err != nil || res == nil || res.Secret != "SECRET" || res.Credentials == nil || res.Credentials.AccessKeyID != "AKID" || res.RoleARN != adminARN {
		t.Errorf("result = %+v, %v", res, err)
	}
	if p, _ := store.ReadPending(); p != nil {
		t.Error("the pending login is still there")
	}
	if roles, _ := store.ReadRoles(); len(roles) != 2 {
		t.Errorf("saved roles = %v", roles)
	}
}

func TestNativeHostRoleDuration(t *testing.T) {
	useTestStore(t)
	calls := fakeSTSWith(t, false, 3600, `readonly = { arn = "`+readonlyARN+`", duration = "12h" }`+"\n")
	writePending(t, store.Pending{RoleARN: readonlyARN})
	r := host(t, hostRequest{SAMLResponse: samlResponse(adminARN, readonlyARN), Nonce: "NONCE"})
	if len(r) != 1 || r[0].Status != "ok" {
		t.Fatalf("replies = %s", statuses(r))
	}
	if got := calls.getDurations(); !slices.Equal(got, []string{"43200", "3600"}) {
		t.Errorf("STS durations = %v, want 12h then the 1h retry", got)
	}
	if res, _ := store.ReadResult(); res == nil || res.Credentials == nil || !strings.Contains(res.Notice, "1h0m0s") {
		t.Errorf("result = %+v", res)
	}
}

func TestNativeHostExchangeFails(t *testing.T) {
	useTestStore(t)
	fakeSTS(t, true)
	writePending(t, store.Pending{RoleARN: adminARN})
	r := host(t, hostRequest{SAMLResponse: samlResponse(adminARN), Nonce: "NONCE"})
	if len(r) != 1 || r[0].Status != "error" || !strings.Contains(r[0].Error, "bad assertion") {
		t.Fatalf("replies = %s", statuses(r))
	}
	if res, _ := store.ReadResult(); res == nil || res.Error == "" || res.Credentials != nil {
		t.Errorf("result = %+v", res)
	}
	if p, _ := store.ReadPending(); p == nil {
		t.Error("a failed exchange ended the pending login")
	}
}

func TestNativeHostListOnly(t *testing.T) {
	useTestStore(t)
	calls := fakeSTS(t, false)
	writePending(t, store.Pending{ListOnly: true})
	r := host(t, hostRequest{SAMLResponse: samlResponse(adminARN, readonlyARN), Nonce: "NONCE"})
	if len(r) != 1 || r[0].Status != "listed" {
		t.Fatalf("replies = %s", statuses(r))
	}
	if res, _ := store.ReadResult(); res == nil || !res.Listed || res.Secret != "SECRET" {
		t.Errorf("result = %+v", res)
	}
	if roles, _ := store.ReadRoles(); len(roles) != 2 {
		t.Errorf("saved roles = %v", roles)
	}
	if len(calls.get()) != 0 {
		t.Errorf("STS called for %v", calls.get())
	}
}

// TestNativeHostChoose answers the host as the waiting login would, first
// with a choice carrying the wrong secret, which the host must ignore.
func TestNativeHostChoose(t *testing.T) {
	useTestStore(t)
	calls := fakeSTS(t, false)
	p := writePending(t, store.Pending{})
	go func() {
		for {
			if res, _ := store.ReadResult(); res != nil && len(res.Roles) == 2 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		_ = store.WriteChoice(store.Choice{Secret: "WRONG", RoleARN: adminARN})
		for c, _ := store.ReadChoice(); c != nil; c, _ = store.ReadChoice() {
			time.Sleep(50 * time.Millisecond)
		}
		_ = store.WriteChoice(store.Choice{Secret: p.Secret, RoleARN: readonlyARN})
	}()
	r := host(t, hostRequest{SAMLResponse: samlResponse(adminARN, readonlyARN), Nonce: "NONCE"})
	if len(r) != 2 || r[0].Status != "choose" || r[1].Status != "ok" || r[1].Role != "readonly" {
		t.Fatalf("replies = %s", statuses(r))
	}
	if !slices.Equal(calls.get(), []string{readonlyARN}) {
		t.Errorf("STS calls = %v", calls.get())
	}
}

func TestAskForRoleTimesOut(t *testing.T) {
	useTestStore(t)
	old := chooseTimeout
	chooseTimeout = 500 * time.Millisecond
	t.Cleanup(func() { chooseTimeout = old })
	if _, err := askForRole("SECRET", []saml.Role{{RoleARN: adminARN, PrincipalARN: providerARN}}); err == nil {
		t.Error("askForRole without a choice succeeded")
	}
}
