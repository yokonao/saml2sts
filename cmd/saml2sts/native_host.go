package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/yokonao/saml2sts/internal/config"
	"github.com/yokonao/saml2sts/internal/federation"
	"github.com/yokonao/saml2sts/internal/nativemsg"
	"github.com/yokonao/saml2sts/internal/saml"
	"github.com/yokonao/saml2sts/internal/store"
)

type hostRequest struct {
	SAMLResponse string `json:"samlResponse"`
	Nonce        string `json:"nonce"`
}

type hostReply struct {
	// Status is "choose" while the user picks a role in the terminal, then
	// "ok", "listed" for a login that wanted only the roles, or "error";
	// "idle" means no login is pending for the nonce.
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	// Role names the role an "ok" signed in to.
	Role string `json:"role,omitempty"`
}

const (
	stsTimeout = 30 * time.Second
	// chooseTimeout bounds how long the host waits for the user to pick a role.
	chooseTimeout = 2 * time.Minute
	pollInterval  = 300 * time.Millisecond
)

// runNativeHost answers one message from the extension, with a "choose" reply
// first when the user has to pick a role. The SAML response never leaves this
// process: it calls STS itself and hands only the credentials to the waiting
// login through secure storage.
func runNativeHost(r io.Reader, w io.Writer) error {
	var req hostRequest
	if err := nativemsg.Read(r, &req); err != nil {
		return nativemsg.Write(w, hostReply{Status: "error", Error: "malformed message"})
	}
	p, err := store.ReadPending()
	if err != nil {
		return nativemsg.Write(w, hostReply{Status: "error", Error: err.Error()})
	}
	if !p.Accepts(req.Nonce, time.Now()) {
		return nativemsg.Write(w, hostReply{Status: "idle"})
	}

	if p.ListOnly {
		return listRoles(w, *p, req.SAMLResponse)
	}

	notify := func() error { return nativemsg.Write(w, hostReply{Status: "choose"}) }
	cfg, c, roleARN, err := exchange(*p, req.SAMLResponse, notify)
	if err != nil {
		// The login stays pending, so the user can sign in again.
		if werr := store.WriteResult(store.Result{Secret: p.Secret, Error: err.Error()}); werr != nil {
			err = errors.Join(err, werr)
		}
		return nativemsg.Write(w, hostReply{Status: "error", Error: err.Error()})
	}
	if err := store.WriteResult(store.Result{Secret: p.Secret, Credentials: &c, RoleARN: roleARN}); err != nil {
		return nativemsg.Write(w, hostReply{Status: "error", Error: err.Error()})
	}
	if err := store.DeletePending(); err != nil {
		return nativemsg.Write(w, hostReply{Status: "error", Error: err.Error()})
	}
	return nativemsg.Write(w, hostReply{Status: "ok", Role: cfg.RoleName(roleARN)})
}

// listRoles saves the roles of the SAML response for a ListOnly login,
// without calling STS.
func listRoles(w io.Writer, p store.Pending, samlResponse string) error {
	roles, err := saml.Roles(samlResponse)
	if err == nil {
		err = store.WriteRoles(roles)
	}
	if err != nil {
		if werr := store.WriteResult(store.Result{Secret: p.Secret, Error: err.Error()}); werr != nil {
			err = errors.Join(err, werr)
		}
		return nativemsg.Write(w, hostReply{Status: "error", Error: err.Error()})
	}
	if err := store.WriteResult(store.Result{Secret: p.Secret, Listed: true}); err != nil {
		return nativemsg.Write(w, hostReply{Status: "error", Error: err.Error()})
	}
	if err := store.DeletePending(); err != nil {
		return nativemsg.Write(w, hostReply{Status: "error", Error: err.Error()})
	}
	return nativemsg.Write(w, hostReply{Status: "listed"})
}

// exchange calls notify before waiting for the user to choose a role.
func exchange(p store.Pending, samlResponse string, notify func() error) (config.Config, federation.Credentials, string, error) {
	cfg, err := config.Load()
	if err != nil {
		return cfg, federation.Credentials{}, "", err
	}
	roles, err := saml.Roles(samlResponse)
	if err != nil {
		return cfg, federation.Credentials{}, "", err
	}
	if err := store.WriteRoles(roles); err != nil {
		return cfg, federation.Credentials{}, "", err
	}
	roleARN := p.RoleARN
	if roleARN == "" && len(roles) > 1 {
		if err := notify(); err != nil {
			return cfg, federation.Credentials{}, "", err
		}
		if roleARN, err = askForRole(p.Secret, roles); err != nil {
			return cfg, federation.Credentials{}, "", err
		}
	}
	role, err := saml.Select(roles, roleARN)
	if err != nil {
		return cfg, federation.Credentials{}, "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), stsTimeout)
	defer cancel()
	c, err := federation.AssumeRole(ctx, cfg.IDP.Region, cfg.IDP.STSEndpoint, role, samlResponse, cfg.IDP.Duration.Duration)
	return cfg, c, role.RoleARN, err
}

// askForRole hands the roles to the waiting login and returns the one the
// user picks there.
func askForRole(secret string, roles []saml.Role) (string, error) {
	if err := store.WriteResult(store.Result{Secret: secret, Roles: roles}); err != nil {
		return "", err
	}
	deadline := time.Now().Add(chooseTimeout)
	for time.Now().Before(deadline) {
		time.Sleep(pollInterval)
		c, err := store.ReadChoice()
		if err != nil {
			return "", err
		}
		if c == nil {
			continue
		}
		if err := store.DeleteChoice(); err != nil {
			return "", err
		}
		if subtle.ConstantTimeCompare([]byte(c.Secret), []byte(secret)) == 1 {
			return c.RoleARN, nil
		}
	}
	return "", errors.New("no role chosen in time")
}

// startedByBrowser reports whether a browser started this process as its
// native messaging host, which it does with arguments no subcommand takes:
// Chromium passes the caller's origin, Firefox the host manifest path and the
// add-on ID.
func startedByBrowser(args []string) bool {
	switch {
	case len(args) >= 1 && strings.HasPrefix(args[0], "chrome-extension://"):
		return true
	case len(args) == 2 && filepath.IsAbs(args[0]) && strings.HasSuffix(args[0], ".json") && firefoxID.MatchString(args[1]):
		return true
	}
	return false
}
