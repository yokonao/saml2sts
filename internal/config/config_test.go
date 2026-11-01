package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckEndpoint(t *testing.T) {
	for s, ok := range map[string]bool{
		"": true,
		"https://sts.ap-northeast-1.amazonaws.com": true,
		"http://127.0.0.1:4566":                    true,
		"http://localhost:4566":                    true,
		"http://[::1]:4566":                        true,
		"http://sts.example.com":                   false,
		"ftp://127.0.0.1":                          false,
		"https://":                                 false,
	} {
		if err := checkEndpoint(s); (err == nil) != ok {
			t.Errorf("checkEndpoint(%q) = %v, want ok=%v", s, err, ok)
		}
	}
}

func load(t *testing.T, body string) (Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	t.Setenv("SAML2STS_CONFIG", path)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load()
}

func TestLoad(t *testing.T) {
	const admin = "arn:aws:iam::111111111111:role/admin"
	c, err := load(t, `
[idp]
url = "https://idp.example.com/sso"
duration = "1h"

[roles]
prod-admin = "`+admin+`"
`)
	if err != nil {
		t.Fatal(err)
	}
	if c.IDP.Region != "us-east-1" || c.IDP.Duration.Hours() != 1 {
		t.Errorf("IDP = %+v", c.IDP)
	}

	for in, want := range map[string]string{
		"prod-admin": admin,
		"arn:aws:iam::222222222222:role/path/dev": "arn:aws:iam::222222222222:role/path/dev",
	} {
		if got, err := c.ResolveRole(in); got != want || err != nil {
			t.Errorf("ResolveRole(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "nope", "arn:aws:iam::1:role/x"} {
		if _, err := c.ResolveRole(in); err == nil {
			t.Errorf("ResolveRole(%q) succeeded", in)
		}
	}

	if got := c.RoleName(admin); got != "prod-admin" {
		t.Errorf("RoleName(alias) = %q", got)
	}
	if got := c.RoleName("arn:aws:iam::222222222222:role/path/dev"); got != "path/dev" {
		t.Errorf("RoleName(unnamed) = %q", got)
	}
}

func TestLoadRejects(t *testing.T) {
	for name, body := range map[string]string{
		"no url":         "[idp]\nregion = \"us-east-1\"",
		"remote http":    "[idp]\nurl = \"https://idp\"\nsts_endpoint = \"http://sts.example.com\"",
		"bad role alias": "[idp]\nurl = \"https://idp\"\n[roles]\nx = \"admin\"",
	} {
		if _, err := load(t, body); err == nil {
			t.Errorf("%s: Load succeeded", name)
		}
	}
}
