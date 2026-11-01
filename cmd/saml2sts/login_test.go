//go:build darwin

package main

import (
	"io"
	"strings"
	"testing"

	"github.com/yokonao/saml2sts/internal/config"
	"github.com/yokonao/saml2sts/internal/saml"
)

func TestChooseRole(t *testing.T) {
	roles := []saml.Role{
		{RoleARN: "arn:aws:iam::111111111111:role/admin"},
		{RoleARN: "arn:aws:iam::222222222222:role/readonly"},
	}
	cfg := config.Config{Roles: map[string]config.Role{"prod-admin": {ARN: roles[0].RoleARN}}}

	var out strings.Builder
	got, err := chooseRole(strings.NewReader("2\n"), &out, cfg, roles)
	if err != nil || got != roles[1] {
		t.Fatalf("chooseRole = %v, %v", got, err)
	}
	if !strings.Contains(out.String(), "1) prod-admin  arn:aws:iam::111111111111:role/admin") {
		t.Errorf("prompt does not show the alias:\n%s", out.String())
	}

	for _, in := range []string{"0\n", "3\n", "x\n", ""} {
		if _, err := chooseRole(strings.NewReader(in), io.Discard, cfg, roles); err == nil {
			t.Errorf("chooseRole(%q) succeeded", in)
		}
	}
}
