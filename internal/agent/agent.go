// Package agent carries role requests from a work machine to saml2sts agent
// on the sign-in machine over a Unix domain socket. Each connection carries
// one request and one response, each a line of JSON.
package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/yokonao/saml2sts/internal/federation"
)

// SockEnv names the variable holding the path of the agent socket on the
// work machine.
const SockEnv = "SAML2STS_AGENT_SOCK"

// Version is the protocol version. The agent rejects requests of another
// version, so both machines need a saml2sts that speaks the same one.
const Version = 1

// Methods of a Request.
const (
	MethodCredentials = "credentials"
	MethodRoles       = "roles"
)

const docsURL = "https://github.com/yokonao/saml2sts/blob/main/docs/agent.md"

// Request asks the agent for credentials or for the roles it shares.
type Request struct {
	Version int    `json:"version"`
	Method  string `json:"method"`
	// Role is an ARN or a name from [roles] in the agent's config.
	Role string `json:"role,omitempty"`
}

// Response answers a Request. Error is set when the agent refused it.
type Response struct {
	Version     int                     `json:"version"`
	Credentials *federation.Credentials `json:"credentials,omitempty"`
	RoleARN     string                  `json:"role_arn,omitempty"`
	Roles       []Role                  `json:"roles,omitempty"`
	Error       string                  `json:"error,omitempty"`
}

// Role is a role the agent shares, with its name from [roles] if any.
type Role struct {
	ARN  string `json:"arn"`
	Name string `json:"name,omitempty"`
}

// Socket returns the agent socket path from SockEnv.
func Socket() (string, error) {
	if s := os.Getenv(SockEnv); s != "" {
		return s, nil
	}
	return "", fmt.Errorf("$%s is not set: run saml2sts agent on the sign-in machine, forward its socket here, e.g. with ssh -R, and point $%s at it; see %s", SockEnv, SockEnv, docsURL)
}

// Credentials asks the agent at sock for credentials of role and returns
// them with the ARN of their role.
func Credentials(ctx context.Context, sock, role string) (federation.Credentials, string, error) {
	r, err := Call(ctx, sock, Request{Method: MethodCredentials, Role: role})
	if err != nil {
		return federation.Credentials{}, "", err
	}
	if r.Credentials == nil || r.RoleARN == "" {
		return federation.Credentials{}, "", errors.New("the agent returned no credentials")
	}
	return *r.Credentials, r.RoleARN, nil
}

// Roles asks the agent at sock for the roles it shares.
func Roles(ctx context.Context, sock string) ([]Role, error) {
	r, err := Call(ctx, sock, Request{Method: MethodRoles})
	if err != nil {
		return nil, err
	}
	return r.Roles, nil
}

// Call sends req to the agent at sock and waits for its response, which may
// take as long as a sign-in in the browser.
func Call(ctx context.Context, sock string, req Request) (Response, error) {
	req.Version = Version
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		return Response{}, fmt.Errorf("cannot reach the agent at %s: %w; check that saml2sts agent runs on the sign-in machine and its socket is forwarded here", sock, err)
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, fmt.Errorf("send to the agent: %w", ctxErr(ctx, err))
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return Response{}, fmt.Errorf("read from the agent: %w", ctxErr(ctx, err))
	}
	var r Response
	if err := json.Unmarshal(line, &r); err != nil {
		return Response{}, fmt.Errorf("read from the agent: %w", err)
	}
	if r.Error != "" {
		return Response{}, fmt.Errorf("agent: %s", r.Error)
	}
	if r.Version != Version {
		return Response{}, fmt.Errorf("the agent speaks protocol version %d, but this saml2sts speaks %d; install the same version on both machines", r.Version, Version)
	}
	return r, nil
}

func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
