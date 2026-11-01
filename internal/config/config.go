// Package config loads $XDG_CONFIG_HOME/saml2sts/config.toml: the IdP to sign
// in with and optional short names for roles.
package config

import (
	"cmp"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the whole file.
type Config struct {
	IDP IDP `toml:"idp"`
	// Roles maps short names to role ARNs.
	Roles map[string]string `toml:"roles"`
}

// IDP is where to sign in and how to reach STS.
type IDP struct {
	// URL starts IdP-initiated SSO to AWS.
	URL      string   `toml:"url"`
	Duration duration `toml:"duration"`
	// Region selects the regional STS endpoint; empty means us-east-1.
	Region string `toml:"region"`
	// STSEndpoint replaces the STS endpoint, such as for a VPC endpoint or a
	// local emulator. The SAML response is sent there.
	STSEndpoint string `toml:"sts_endpoint"`
}

type duration struct{ time.Duration }

func (d *duration) UnmarshalText(b []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(b))
	return err
}

var (
	validRegion = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)
	roleARN     = regexp.MustCompile(`^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+$`)
)

// Path returns the config file path; $SAML2STS_CONFIG overrides it.
func Path() (string, error) {
	if p := os.Getenv("SAML2STS_CONFIG"); p != "" {
		return p, nil
	}
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "saml2sts", "config.toml"), nil
}

// Load reads and validates the config file.
func Load() (Config, error) {
	path, err := Path()
	if err != nil {
		return Config{}, err
	}
	var c Config
	if _, err := toml.DecodeFile(path, &c); err != nil {
		return Config{}, err
	}
	if c.IDP.URL == "" {
		return Config{}, fmt.Errorf("%s has no [idp] url", path)
	}
	c.IDP.Region = cmp.Or(c.IDP.Region, "us-east-1")
	if !validRegion.MatchString(c.IDP.Region) {
		return Config{}, fmt.Errorf("invalid [idp] region %q", c.IDP.Region)
	}
	if err := checkEndpoint(c.IDP.STSEndpoint); err != nil {
		return Config{}, err
	}
	for name, arn := range c.Roles {
		if !roleARN.MatchString(arn) {
			return Config{}, fmt.Errorf("[roles] %s is not a role ARN: %q", name, arn)
		}
	}
	return c, nil
}

// ResolveRole turns a short name from [roles], or a role ARN, into a role ARN.
func (c Config) ResolveRole(role string) (string, error) {
	if arn, ok := c.Roles[role]; ok {
		return arn, nil
	}
	if roleARN.MatchString(role) {
		return role, nil
	}
	if role == "" {
		return "", errors.New("no role given")
	}
	return "", fmt.Errorf("%q is neither a role ARN nor a name in [roles]", role)
}

// Alias returns the name [roles] gives arn, if any.
func (c Config) Alias(arn string) (string, bool) {
	for name, a := range c.Roles {
		if a == arn {
			return name, true
		}
	}
	return "", false
}

// RoleName returns the short name of arn, or the part after "role/".
func (c Config) RoleName(arn string) string {
	if name, ok := c.Alias(arn); ok {
		return name
	}
	_, after, _ := strings.Cut(arn, ":role/")
	return cmp.Or(after, arn)
}

// checkEndpoint allows plain HTTP only to this machine, so the SAML response
// never crosses the network unencrypted.
func checkEndpoint(s string) error {
	if s == "" {
		return nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("invalid sts_endpoint: %w", err)
	}
	switch {
	case u.Scheme == "https" && u.Host != "":
		return nil
	case u.Scheme == "http":
		if ip := net.ParseIP(u.Hostname()); u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return fmt.Errorf("sts_endpoint %q must be https, or http to localhost", s)
}
