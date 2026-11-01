//go:build darwin

// These tests need a temporary directory that no other user can write to,
// as on macOS but not under /tmp on Linux. The system config is for macOS.

package config

import (
	"path/filepath"
	"testing"

	"github.com/yokonao/saml2sts/internal/rootowned"
)

func TestSystemConfig(t *testing.T) {
	const sysAdmin, userAdmin = "arn:aws:iam::111111111111:role/org-admin", "arn:aws:iam::111111111111:role/admin"
	sys := useSystem(t, `
[idp]
url = "https://idp.example.com/org"
sts_endpoint = ""
region = "ap-northeast-1"

[roles]
admin = "`+sysAdmin+`"
`)
	c, err := load(t, `
[idp]
url = "https://evil.example.com/sso"
sts_endpoint = "https://evil.example.com"
duration = "2h"

[roles]
admin = "`+userAdmin+`"
dev = "arn:aws:iam::111111111111:role/dev"
`)
	if err != nil {
		t.Fatal(err)
	}
	if c.IDP.URL != "https://idp.example.com/org" || c.IDP.STSEndpoint != "" || c.IDP.Region != "ap-northeast-1" || c.IDP.Duration.Hours() != 2 {
		t.Errorf("IDP = %+v", c.IDP)
	}
	if c.Sources["idp.url"] != sys || c.Sources["idp.sts_endpoint"] != sys || c.Sources["idp.duration"] == sys {
		t.Errorf("Sources = %v", c.Sources)
	}
	if c.Roles["admin"].ARN != sysAdmin || c.Roles["dev"].ARN == "" {
		t.Errorf("Roles = %v", c.Roles)
	}
}

func TestSystemConfigWithoutUserConfig(t *testing.T) {
	useSystem(t, "[idp]\nurl = \"https://idp.example.com/org\"\n")
	t.Setenv("SAML2STS_CONFIG", filepath.Join(t.TempDir(), "missing.toml"))
	c, err := Load()
	if err != nil || c.IDP.URL != "https://idp.example.com/org" {
		t.Errorf("Load = %+v, %v", c.IDP, err)
	}
}

func TestSystemConfigMustBeRootOwned(t *testing.T) {
	sys := useSystem(t, "[idp]\nurl = \"https://idp.example.com/org\"\n")
	rootowned.Owners = nil
	if _, err := load(t, "[idp]\nurl = \"https://idp\"\n"); err == nil {
		t.Errorf("Load accepted %s owned by the user", sys)
	}
}

func TestSystemRemote(t *testing.T) {
	const dev, admin = "arn:aws:iam::111111111111:role/dev", "arn:aws:iam::111111111111:role/admin"
	useSystem(t, `
[remote]
accounts = ["111111111111"]
confirm = ["`+admin+`"]
`)
	c, err := load(t, `
[idp]
url = "https://idp.example.com/sso"

[remote]
accounts = ["222222222222"]
roles = ["`+dev+`"]
confirm = ["`+dev+`"]
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Remote.Accounts) != 1 || c.Remote.Accounts[0] != "111111111111" || len(c.Remote.Roles) != 1 {
		t.Errorf("Remote = %+v", c.Remote)
	}
	if !c.Remote.NeedsConfirm(admin) || !c.Remote.NeedsConfirm(dev) {
		t.Errorf("Confirm = %v", c.Remote.Confirm)
	}
}
