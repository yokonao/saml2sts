//go:build darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/yokonao/saml2sts/internal/agent"
	"github.com/yokonao/saml2sts/internal/config"
	"github.com/yokonao/saml2sts/internal/federation"
	"github.com/yokonao/saml2sts/internal/login"
	"github.com/yokonao/saml2sts/internal/saml"
	"github.com/yokonao/saml2sts/internal/store"
)

// maxSockPath is the size of sun_path on macOS, less its terminating NUL.
const maxSockPath = 103

func newAgentCmd() *cobra.Command {
	var (
		sock    string
		timeout time.Duration
	)
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Serve credentials of the roles [remote] names to work machines over a Unix domain socket",
		Long: `Serve credentials to work machines over a Unix domain socket, which you forward to them, such as with ssh -R.

This resident agent shares only the accounts and roles [remote] names in the config file. Every request shows a notification, and roles in [remote] confirm need your approval in a dialog.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if sock == "" {
				dir, err := os.UserCacheDir()
				if err != nil {
					return err
				}
				sock = filepath.Join(dir, "saml2sts", "agent.sock")
			}
			l, err := listenResident(sock)
			if err != nil {
				return err
			}
			defer func() { _ = l.Close() }()
			logf(cmd.ErrOrStderr(), "agent listening on %s\n", sock)
			if cfg, err := config.Load(); err == nil && len(cfg.Remote.Accounts) == 0 && len(cfg.Remote.Roles) == 0 {
				logf(cmd.ErrOrStderr(), "[remote] names no account or role, so every request will be refused\n")
			}
			h := newAgentHandler(cmd.ErrOrStderr(), "socket "+sock, false, timeout)
			return agent.Serve(cmd.Context(), l, h.handle)
		},
	}
	cmd.Flags().StringVar(&sock, "socket", "", "socket path (default ~/Library/Caches/saml2sts/agent.sock)")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "how long to wait for each browser sign-in")
	cmd.AddCommand(newAgentExecCmd())
	return cmd
}

func newAgentExecCmd() *cobra.Command {
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "exec -- <command> [args...]",
		Short: "Run a command, such as ssh, with a temporary agent that shares every role until it exits",
		Long: `Run a command with a temporary agent, whose socket path is in $SAML2STS_AGENT_SOCK for the command to forward, such as with RemoteForward in ~/.ssh/config.

The agent shares every role your IdP allows, and stops and removes its socket when the command exits. Every request shows a notification, and roles in [remote] confirm need your approval in a dialog.`,
		Example: `  # ~/.ssh/config
  Host devbox
    RemoteForward /home/me/.saml2sts/agent.sock ${SAML2STS_AGENT_SOCK}

  saml2sts agent exec -- ssh devbox`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			code, err := runWithAgent(cmd.Context(), cmd.ErrOrStderr(), args, timeout)
			if err != nil {
				return err
			}
			if code != 0 {
				os.Exit(code)
			}
			return nil
		},
	}
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "how long to wait for each browser sign-in")
	return cmd
}

// runWithAgent runs args with a temporary agent and returns its exit code.
func runWithAgent(ctx context.Context, log io.Writer, args []string, timeout time.Duration) (int, error) {
	dir, err := os.MkdirTemp("", "saml2sts-agent-")
	if err != nil {
		return 0, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	sock := filepath.Join(dir, "agent.sock")
	l, err := listen(sock)
	if err != nil {
		return 0, err
	}

	ctx, cancel := context.WithCancel(ctx)
	h := newAgentHandler(log, strings.Join(args, " "), true, timeout)
	served := make(chan error, 1)
	go func() { served <- agent.Serve(ctx, l, h.handle) }()
	defer func() {
		cancel()
		if err := <-served; err != nil {
			logf(log, "agent stopped: %v\n", err)
		}
	}()

	c := exec.Command(args[0], args[1:]...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	c.Env = append(withoutEnv(os.Environ(), agent.SockEnv), agent.SockEnv+"="+sock)
	err = c.Run()
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		return ee.ExitCode(), nil
	}
	return 0, err
}

func withoutEnv(env []string, key string) []string {
	var out []string
	for _, kv := range env {
		if k, _, _ := strings.Cut(kv, "="); k != key {
			out = append(out, kv)
		}
	}
	return out
}

// listenResident listens on sock in place of a socket an earlier agent left,
// but not of an agent still listening.
func listenResident(sock string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		return nil, err
	}
	if conn, err := net.Dial("unix", sock); err == nil {
		_ = conn.Close()
		return nil, fmt.Errorf("an agent already listens on %s", sock)
	}
	if err := os.Remove(sock); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return listen(sock)
}

func listen(sock string) (net.Listener, error) {
	if len(sock) > maxSockPath {
		return nil, fmt.Errorf("socket path %s is longer than %d bytes", sock, maxSockPath)
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

// agentHandler answers requests from work machines. Its functions are
// fields so tests can replace them.
type agentHandler struct {
	log io.Writer
	// from says where requests come from, in notifications.
	from string
	// shareAll shares every role, as a temporary agent does, instead of
	// those [remote] names.
	shareAll bool

	loadConfig  func() (config.Config, error)
	savedRoles  func() ([]saml.Role, error)
	credentials func(ctx context.Context, cfg config.Config, arn string) (federation.Credentials, string, error)
	notify      func(msg string)
	confirm     func(ctx context.Context, msg string) (bool, error)
}

func newAgentHandler(log io.Writer, from string, shareAll bool, timeout time.Duration) *agentHandler {
	return &agentHandler{
		log:        log,
		from:       from,
		shareAll:   shareAll,
		loadConfig: config.Load,
		savedRoles: store.ReadRoles,
		credentials: func(ctx context.Context, cfg config.Config, arn string) (federation.Credentials, string, error) {
			return login.Credentials(ctx, cfg, arn, login.Options{Timeout: timeout, Log: log})
		},
		notify: func(msg string) {
			if err := notify(msg); err != nil {
				logf(log, "notification failed: %v\n", err)
			}
		},
		confirm: confirm,
	}
}

func (h *agentHandler) handle(ctx context.Context, req agent.Request) agent.Response {
	cfg, err := h.loadConfig()
	if err != nil {
		return h.refuse(err)
	}
	switch req.Method {
	case agent.MethodRoles:
		return h.roles(cfg)
	case agent.MethodCredentials:
		return h.issue(ctx, cfg, req.Role)
	}
	return h.refuse(fmt.Errorf("unknown method %q", req.Method))
}

func (h *agentHandler) roles(cfg config.Config) agent.Response {
	saved, err := h.savedRoles()
	if err != nil {
		return h.refuse(err)
	}
	if len(saved) == 0 {
		return h.refuse(errors.New("no roles yet; run saml2sts login or profiles sync on the sign-in machine once"))
	}
	roles := []agent.Role{}
	for _, r := range saved {
		if h.shares(cfg, r.RoleARN) {
			name, _ := cfg.Alias(r.RoleARN)
			roles = append(roles, agent.Role{ARN: r.RoleARN, Name: name})
		}
	}
	return agent.Response{Roles: roles}
}

func (h *agentHandler) issue(ctx context.Context, cfg config.Config, role string) agent.Response {
	arn, err := cfg.ResolveRole(role)
	if err != nil {
		return h.refuse(err)
	}
	if !h.shares(cfg, arn) {
		return h.refuse(fmt.Errorf("%s is not shared with work machines; add its account or the role to [remote] in the config on the sign-in machine", arn))
	}
	msg := fmt.Sprintf("%s asks for %s", h.from, cfg.RoleName(arn))
	logf(h.log, "%s (%s)\n", msg, arn)
	h.notify(msg)
	if cfg.Remote.NeedsConfirm(arn) {
		ok, err := h.confirm(ctx, msg+".\n\n"+arn)
		if err != nil {
			return h.refuse(fmt.Errorf("ask for approval on the sign-in machine: %w", err))
		}
		if !ok {
			return h.refuse(fmt.Errorf("%s was not allowed on the sign-in machine", arn))
		}
	}
	c, arn, err := h.credentials(ctx, cfg, arn)
	if err != nil {
		return h.refuse(err)
	}
	return agent.Response{Credentials: &c, RoleARN: arn}
}

func (h *agentHandler) shares(cfg config.Config, arn string) bool {
	return h.shareAll || cfg.Remote.Shares(arn)
}

func (h *agentHandler) refuse(err error) agent.Response {
	logf(h.log, "refused: %v\n", err)
	return agent.Response{Error: err.Error()}
}

func logf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, "saml2sts: "+format, args...)
}

// The scripts take the text as an argument, so a role name from a work
// machine cannot change them.
const (
	notifyScript = `on run argv
	display notification (item 1 of argv) with title "saml2sts agent"
end run`
	confirmScript = `on run argv
	display dialog (item 1 of argv) with title "saml2sts agent" buttons {"Deny", "Allow"} default button "Deny" giving up after 60 with icon caution
	return button returned of result
end run`
)

func notify(msg string) error {
	return exec.Command("osascript", "-e", notifyScript, msg).Run()
}

// confirm asks the user in a dialog; no answer within a minute denies.
func confirm(ctx context.Context, msg string) (bool, error) {
	out, err := exec.CommandContext(ctx, "osascript", "-e", confirmScript, msg).Output()
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(out)) == "Allow", nil
}
