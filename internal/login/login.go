// Package login gets credentials for a role from the cache or by signing in
// through the browser.
package login

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"time"

	"github.com/yokonao/saml2sts/internal/config"
	"github.com/yokonao/saml2sts/internal/federation"
	"github.com/yokonao/saml2sts/internal/flock"
	"github.com/yokonao/saml2sts/internal/saml"
	"github.com/yokonao/saml2sts/internal/store"
)

// refreshMargin exceeds botocore's 15-minute advisory refresh window, so the
// AWS CLI does not call credential_process again right after a login.
const refreshMargin = 16 * time.Minute

const pollInterval = 500 * time.Millisecond

// Options control Credentials.
type Options struct {
	// Force signs in even when cached credentials are valid.
	Force bool
	// NoOpen prints the IdP URL instead of opening the browser.
	NoOpen bool
	// Timeout bounds the wait for the browser sign-in.
	Timeout time.Duration
	// Log receives progress messages; stdout may carry credential_process output.
	Log io.Writer
	// Choose picks a role after the sign-in when none was given.
	Choose func([]saml.Role) (saml.Role, error)
}

// Credentials returns credentials for roleARN and the role they are for. An
// empty roleARN signs in and lets opts.Choose pick among the allowed roles.
func Credentials(ctx context.Context, cfg config.Config, roleARN string, opts Options) (federation.Credentials, string, error) {
	unlock, err := lock()
	if err != nil {
		return federation.Credentials{}, "", err
	}
	defer unlock()

	if roleARN != "" && !opts.Force {
		c, err := store.ReadCache(roleARN)
		if err != nil {
			opts.logf("saml2sts: ignoring cache: %v\n", err)
		}
		if c != nil && c.Fresh(refreshMargin) {
			return *c, roleARN, nil
		}
	}
	if roleARN == "" && opts.Choose == nil {
		return federation.Credentials{}, "", errors.New("no role given")
	}

	r, err := signIn(ctx, cfg, store.Pending{RoleARN: roleARN}, opts)
	if err != nil {
		return federation.Credentials{}, "", err
	}
	if r.Credentials == nil {
		return federation.Credentials{}, "", errors.New("the sign-in returned no credentials")
	}
	if r.Notice != "" {
		opts.logf("saml2sts: %s\n", r.Notice)
	}
	if err := store.WriteCache(r.RoleARN, *r.Credentials); err != nil {
		opts.logf("saml2sts: credentials not cached: %v\n", err)
	}
	return *r.Credentials, r.RoleARN, nil
}

// ListRoles signs in only to save the roles the IdP allows, assuming none.
func ListRoles(ctx context.Context, cfg config.Config, opts Options) error {
	unlock, err := lock()
	if err != nil {
		return err
	}
	defer unlock()
	_, err = signIn(ctx, cfg, store.Pending{ListOnly: true}, opts)
	return err
}

func signIn(ctx context.Context, cfg config.Config, p store.Pending, opts Options) (*store.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	secret := rand.Text()
	p.Secret = secret
	p.Nonce = rand.Text()
	p.Expires = time.Now().Add(opts.Timeout)
	if err := store.WritePending(p); err != nil {
		return nil, err
	}
	defer func() {
		_ = store.DeletePending()
		_ = store.DeleteResult()
		_ = store.DeleteChoice()
	}()

	u, err := idpURL(cfg.IDP.URL, p.Nonce)
	if err != nil {
		return nil, err
	}
	if opts.NoOpen {
		opts.logf("saml2sts: open %s\n", u)
	} else {
		opts.logf("saml2sts: signing in through the browser\n")
		if err := exec.Command("open", u).Run(); err != nil {
			opts.logf("saml2sts: open %s yourself: %v\n", u, err)
		}
	}

	t := time.NewTicker(pollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, fmt.Errorf("no sign-in within %s", opts.Timeout)
			}
			return nil, ctx.Err()
		case <-t.C:
		}
		r, err := store.ReadResult()
		if err != nil {
			return nil, err
		}
		if r == nil {
			continue
		}
		if err := store.DeleteResult(); err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare([]byte(r.Secret), []byte(secret)) != 1 {
			opts.logf("saml2sts: ignoring a result that does not match this login\n")
			continue
		}
		switch {
		case len(r.Roles) > 0:
			role, err := opts.Choose(r.Roles)
			if err != nil {
				return nil, err
			}
			if err := store.WriteChoice(store.Choice{Secret: secret, RoleARN: role.RoleARN}); err != nil {
				return nil, err
			}
		case r.Error != "":
			// The host keeps the login pending, so another sign-in can still answer it.
			opts.logf("saml2sts: %s; still waiting\n", r.Error)
		case r.Listed || r.Credentials != nil:
			return r, nil
		}
	}
}

// idpURL adds the nonce to the fragment of the IdP URL, which the browser
// does not send to the IdP but the extension sees.
func idpURL(raw, nonce string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("idp.url: %w", err)
	}
	f := "saml2sts=" + nonce
	if u.Fragment != "" {
		f = u.Fragment + "&" + f
	}
	u.Fragment = f
	return u.String(), nil
}

// lock serializes logins, so concurrent credential_process calls open the
// browser once and the rest read the cache.
func lock() (func(), error) { return flock.Lock("lock") }

func (o Options) logf(format string, args ...any) {
	_, _ = fmt.Fprintf(o.Log, format, args...)
}
