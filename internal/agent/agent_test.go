package agent

import (
	"bufio"
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

// serve answers one connection on a new socket with reply and returns the
// socket path and the request it got.
func serve(t *testing.T, reply func(Request) Response) (string, <-chan Request) {
	t.Helper()
	// t.TempDir is too long for a socket path on macOS.
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
	t.Cleanup(func() { _ = l.Close() })
	got := make(chan Request, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		line, err := bufio.NewReader(conn).ReadBytes('\n')
		if err != nil {
			return
		}
		var req Request
		_ = json.Unmarshal(line, &req)
		got <- req
		_ = json.NewEncoder(conn).Encode(reply(req))
	}()
	return sock, got
}

func TestCredentials(t *testing.T) {
	want := federation.Credentials{AccessKeyID: "AKIA", SecretAccessKey: "s", SessionToken: "t", Expiration: time.Now().Add(time.Hour).UTC().Truncate(time.Second)}
	sock, got := serve(t, func(Request) Response {
		return Response{Version: Version, Credentials: &want, RoleARN: "arn:aws:iam::1:role/dev"}
	})
	c, arn, err := Credentials(context.Background(), sock, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessKeyID != want.AccessKeyID || !c.Expiration.Equal(want.Expiration) || arn != "arn:aws:iam::1:role/dev" {
		t.Errorf("got %+v %s", c, arn)
	}
	if req := <-got; req != (Request{Version: Version, Method: MethodCredentials, Role: "dev"}) {
		t.Errorf("request %+v", req)
	}
}

func TestRoles(t *testing.T) {
	sock, _ := serve(t, func(Request) Response {
		return Response{Version: Version, Roles: []Role{{ARN: "arn:aws:iam::1:role/dev", Name: "dev"}}}
	})
	roles, err := Roles(context.Background(), sock)
	if err != nil || len(roles) != 1 || roles[0].Name != "dev" {
		t.Errorf("got %v, %v", roles, err)
	}
}

func TestCallErrors(t *testing.T) {
	tests := map[string]struct {
		reply Response
		want  string
	}{
		"refused":       {Response{Version: Version, Error: "role not shared"}, "agent: role not shared"},
		"other version": {Response{Version: Version + 1}, "protocol version"},
		"no creds":      {Response{Version: Version}, "no credentials"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			sock, _ := serve(t, func(Request) Response { return tt.reply })
			_, _, err := Credentials(context.Background(), sock, "dev")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("got %v, want %q", err, tt.want)
			}
		})
	}
}

func TestUnreachable(t *testing.T) {
	_, _, err := Credentials(context.Background(), filepath.Join(t.TempDir(), "none"), "dev")
	if err == nil || !strings.Contains(err.Error(), "forwarded") {
		t.Errorf("got %v", err)
	}
}

func TestSocketUnset(t *testing.T) {
	t.Setenv(SockEnv, "")
	if _, err := Socket(); err == nil || !strings.Contains(err.Error(), "ssh -R") {
		t.Errorf("got %v", err)
	}
}

func TestCallCanceled(t *testing.T) {
	sock, _ := serve(t, func(Request) Response {
		time.Sleep(time.Second)
		return Response{Version: Version}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := Call(ctx, sock, Request{Method: MethodRoles}); err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Errorf("got %v", err)
	}
}
