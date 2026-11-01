//go:build darwin

package main

import "testing"

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"saml2sts":                "saml2sts",
		"/usr/local/bin/saml2sts": "/usr/local/bin/saml2sts",
		"/Users/a b/bin/saml2sts": "'/Users/a b/bin/saml2sts'",
		"/tmp/it's/saml2sts":      `'/tmp/it'\''s/saml2sts'`,
	} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}
