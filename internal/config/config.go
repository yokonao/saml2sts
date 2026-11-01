// Package config loads the system config, which an organization manages, and
// $XDG_CONFIG_HOME/saml2sts/config.toml: the IdP to sign in with and optional
// short names for roles. Settings of the system config win.
package config

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/yokonao/saml2sts/internal/rootowned"
)

// Config is the whole file.
type Config struct {
	IDP IDP `toml:"idp"`
	// Roles maps short names to roles.
	Roles map[string]Role `toml:"roles"`
	// Profiles maps AWS profile names to role ARNs, or names from Roles,
	// for profiles sync to write instead of its own names. Load resolves
	// them to ARNs.
	Profiles map[string]string `toml:"profiles"`
	// Sources maps each [idp] key set to the file that set it, such as
	// "idp.url".
	Sources map[string]string `toml:"-"`
}

// Role is a role ARN, written as a string or as a table that also sets the
// session duration of the role.
type Role struct {
	ARN string
	// Duration overrides [idp] duration for this role.
	Duration time.Duration
}

func (r *Role) UnmarshalTOML(v any) error {
	switch v := v.(type) {
	case string:
		r.ARN = v
		return nil
	case map[string]any:
		for k, val := range v {
			s, ok := val.(string)
			if !ok {
				return fmt.Errorf("%s must be a string", k)
			}
			switch k {
			case "arn":
				r.ARN = s
			case "duration":
				d, err := time.ParseDuration(s)
				if err != nil {
					return err
				}
				r.Duration = d
			default:
				return fmt.Errorf("unknown key %q", k)
			}
		}
		return nil
	}
	return fmt.Errorf("must be a role ARN or a table with arn and duration, not %T", v)
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

// SystemPath is the config an organization manages. It must be owned by root,
// and no environment variable moves it, so a program running as the user
// cannot change what it sets.
var SystemPath = "/Library/Application Support/saml2sts/config.toml"

var idpKeys = []string{"url", "duration", "region", "sts_endpoint"}

// Files returns the config files that exist, the system one first.
func Files() ([]string, error) {
	user, err := Path()
	if err != nil {
		return nil, err
	}
	var files []string
	for _, p := range []string{SystemPath, user} {
		if _, err := os.Stat(p); err == nil {
			files = append(files, p)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	return files, nil
}

// Load reads, merges and validates the config files.
func Load() (Config, error) {
	user, err := Path()
	if err != nil {
		return Config{}, err
	}
	sys, sysMeta, err := decode(SystemPath, true)
	if err != nil {
		return Config{}, err
	}
	c, userMeta, err := decode(user, sysMeta != nil)
	if err != nil {
		return Config{}, err
	}
	c.Sources = map[string]string{}
	for _, k := range idpKeys {
		if userMeta != nil && userMeta.IsDefined("idp", k) {
			c.Sources["idp."+k] = user
		}
	}
	if sysMeta != nil {
		if err := rootowned.Check(SystemPath); err != nil {
			return Config{}, fmt.Errorf("system config: %w", err)
		}
		merge(&c, sys, sysMeta)
	}
	if c.IDP.URL == "" {
		return Config{}, fmt.Errorf("no [idp] url in %s or %s", user, SystemPath)
	}
	c.IDP.Region = cmp.Or(c.IDP.Region, "us-east-1")
	if !validRegion.MatchString(c.IDP.Region) {
		return Config{}, fmt.Errorf("invalid [idp] region %q", c.IDP.Region)
	}
	if err := checkEndpoint(c.IDP.STSEndpoint); err != nil {
		return Config{}, err
	}
	durations := map[string]time.Duration{}
	for name, r := range c.Roles {
		if !roleARN.MatchString(r.ARN) {
			return Config{}, fmt.Errorf("[roles] %s is not a role ARN: %q", name, r.ARN)
		}
		if r.Duration < 0 {
			return Config{}, fmt.Errorf("[roles] %s has a negative duration", name)
		}
		if d, ok := durations[r.ARN]; ok && d != r.Duration {
			return Config{}, fmt.Errorf("[roles] gives %s different durations", r.ARN)
		}
		durations[r.ARN] = r.Duration
	}
	for name, role := range c.Profiles {
		arn, err := c.ResolveRole(role)
		if err != nil {
			return Config{}, fmt.Errorf("[profiles] %s: %w", name, err)
		}
		c.Profiles[name] = arn
	}
	return c, nil
}

// decode reads path, returning nil metadata when it does not exist and
// optional is set.
func decode(path string, optional bool) (Config, *toml.MetaData, error) {
	var c Config
	md, err := toml.DecodeFile(path, &c)
	if errors.Is(err, os.ErrNotExist) && optional {
		return Config{}, nil, nil
	}
	if err != nil {
		return Config{}, nil, err
	}
	return c, &md, nil
}

// merge puts the settings sys sets over those of c.
func merge(c *Config, sys Config, md *toml.MetaData) {
	set := func(key string, dst *string, v string) {
		if md.IsDefined("idp", key) {
			*dst = v
			c.Sources["idp."+key] = SystemPath
		}
	}
	set("url", &c.IDP.URL, sys.IDP.URL)
	set("region", &c.IDP.Region, sys.IDP.Region)
	set("sts_endpoint", &c.IDP.STSEndpoint, sys.IDP.STSEndpoint)
	if md.IsDefined("idp", "duration") {
		c.IDP.Duration = sys.IDP.Duration
		c.Sources["idp.duration"] = SystemPath
	}
	if len(sys.Roles) > 0 && c.Roles == nil {
		c.Roles = map[string]Role{}
	}
	maps.Copy(c.Roles, sys.Roles)
	if len(sys.Profiles) > 0 && c.Profiles == nil {
		c.Profiles = map[string]string{}
	}
	maps.Copy(c.Profiles, sys.Profiles)
}

// ResolveRole turns a short name from [roles], or a role ARN, into a role ARN.
func (c Config) ResolveRole(role string) (string, error) {
	if r, ok := c.Roles[role]; ok {
		return r.ARN, nil
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
	for name, r := range c.Roles {
		if r.ARN == arn {
			return name, true
		}
	}
	return "", false
}

// ProfileNames returns the names [profiles] gives the profiles of arn, sorted.
func (c Config) ProfileNames(arn string) []string {
	var names []string
	for name, a := range c.Profiles {
		if a == arn {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// Duration returns the session duration to ask STS for arn: its own from
// [roles], else [idp] duration. Zero leaves it to STS.
func (c Config) Duration(arn string) time.Duration {
	for _, r := range c.Roles {
		if r.ARN == arn && r.Duration > 0 {
			return r.Duration
		}
	}
	return c.IDP.Duration.Duration
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
