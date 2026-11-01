//go:build darwin

package main

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yokonao/saml2sts/internal/agent"
	"github.com/yokonao/saml2sts/internal/config"
	"github.com/yokonao/saml2sts/internal/federation"
	"github.com/yokonao/saml2sts/internal/saml"
)

const (
	agentDevARN   = "arn:aws:iam::111111111111:role/dev"
	agentAdminARN = "arn:aws:iam::111111111111:role/admin"
	agentProdARN  = "arn:aws:iam::222222222222:role/admin"
)

type fakeAgent struct {
	*agentHandler
	notified []string
	asked    []string
	allow    bool
	issued   []string
}

func newFakeAgent(shareAll bool) *fakeAgent {
	f := &fakeAgent{}
	f.agentHandler = &agentHandler{
		log:      io.Discard,
		from:     "ssh devbox",
		shareAll: shareAll,
		loadConfig: func() (config.Config, error) {
			return config.Config{
				Roles:  map[string]config.Role{"dev": {ARN: agentDevARN}},
				Remote: config.Remote{Accounts: []string{"111111111111"}, Confirm: []string{agentAdminARN}},
			}, nil
		},
		savedRoles: func() ([]saml.Role, error) {
			return []saml.Role{{RoleARN: agentDevARN}, {RoleARN: agentAdminARN}, {RoleARN: agentProdARN}}, nil
		},
		credentials: func(_ context.Context, _ config.Config, arn string) (federation.Credentials, string, error) {
			f.issued = append(f.issued, arn)
			return federation.Credentials{AccessKeyID: "AKIA"}, arn, nil
		},
		notify: func(msg string) { f.notified = append(f.notified, msg) },
		confirm: func(_ context.Context, msg string) (bool, error) {
			f.asked = append(f.asked, msg)
			return f.allow, nil
		},
	}
	return f
}

func (f *fakeAgent) request(role string) agent.Response {
	return f.handle(context.Background(), agent.Request{Version: agent.Version, Method: agent.MethodCredentials, Role: role})
}

func TestAgentResidentSharesOnlyRemote(t *testing.T) {
	f := newFakeAgent(false)
	if r := f.request("dev"); r.Error != "" || r.RoleARN != agentDevARN {
		t.Errorf("dev: %+v", r)
	}
	if r := f.request(agentProdARN); !strings.Contains(r.Error, "not shared") {
		t.Errorf("prod: %+v", r)
	}
	if len(f.issued) != 1 || len(f.notified) != 1 || !strings.Contains(f.notified[0], "ssh devbox asks for dev") {
		t.Errorf("issued %v, notified %v", f.issued, f.notified)
	}

	r := f.handle(context.Background(), agent.Request{Version: agent.Version, Method: agent.MethodRoles})
	if r.Error != "" || len(r.Roles) != 2 || r.Roles[0] != (agent.Role{ARN: agentDevARN, Name: "dev"}) {
		t.Errorf("roles: %+v", r)
	}
}

func TestAgentTemporarySharesAll(t *testing.T) {
	f := newFakeAgent(true)
	if r := f.request(agentProdARN); r.Error != "" {
		t.Errorf("prod: %+v", r)
	}
	r := f.handle(context.Background(), agent.Request{Version: agent.Version, Method: agent.MethodRoles})
	if len(r.Roles) != 3 {
		t.Errorf("roles: %+v", r)
	}
}

func TestAgentConfirm(t *testing.T) {
	f := newFakeAgent(false)
	if r := f.request(agentAdminARN); !strings.Contains(r.Error, "not allowed") {
		t.Errorf("denied: %+v", r)
	}
	f.allow = true
	if r := f.request(agentAdminARN); r.Error != "" {
		t.Errorf("allowed: %+v", r)
	}
	if len(f.asked) != 2 || len(f.issued) != 1 || !strings.Contains(f.asked[0], agentAdminARN) {
		t.Errorf("asked %v, issued %v", f.asked, f.issued)
	}
}

func TestRunWithAgent(t *testing.T) {
	t.Setenv(agent.SockEnv, "/elsewhere")
	out, err := os.CreateTemp(t.TempDir(), "sock")
	if err != nil {
		t.Fatal(err)
	}
	code, err := runWithAgent(context.Background(), io.Discard,
		[]string{"sh", "-c", `test -S "$SAML2STS_AGENT_SOCK" && printf %s "$SAML2STS_AGENT_SOCK" > "$0"; exit 3`, out.Name()}, time.Minute)
	if err != nil || code != 3 {
		t.Fatalf("runWithAgent = %d, %v", code, err)
	}
	b, err := os.ReadFile(out.Name())
	if err != nil || len(b) == 0 || string(b) == "/elsewhere" {
		t.Fatalf("the command saw socket %q, %v", b, err)
	}
	if _, err := os.Stat(string(b)); !os.IsNotExist(err) {
		t.Errorf("the socket is left behind: %v", err)
	}
}

func TestListenResidentReplacesStaleSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "agent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := dir + "/agent.sock"
	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := listenResident(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	if _, err := listenResident(sock); err == nil || !strings.Contains(err.Error(), "already listens") {
		t.Errorf("second agent: %v", err)
	}
	if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("socket mode: %v, %v", fi.Mode(), err)
	}
}
