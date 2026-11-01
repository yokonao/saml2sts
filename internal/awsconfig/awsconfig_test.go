package awsconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProfileName(t *testing.T) {
	for _, tt := range []struct{ alias, arn, want string }{
		{"prod-admin", "arn:aws:iam::111111111111:role/admin", "saml2sts-prod-admin"},
		{"", "arn:aws:iam::111111111111:role/admin", "saml2sts-111111111111-admin"},
		{"", "arn:aws:iam::111111111111:role/team/dev", "saml2sts-111111111111-team-dev"},
	} {
		if got := ProfileName(tt.alias, tt.arn); got != tt.want {
			t.Errorf("ProfileName(%q, %q) = %q, want %q", tt.alias, tt.arn, got, tt.want)
		}
	}
}

func TestSync(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	const before = `# my settings
[default]
region = ap-northeast-1

[profile saml2sts-gone]
# managed by saml2sts profiles sync
credential_process = saml2sts creds --role arn:aws:iam::111111111111:role/gone

# work account
[profile work]
region = us-west-2
`
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatal(err)
	}

	profiles := []Profile{
		{Name: "saml2sts-b", CredentialProcess: "saml2sts creds --role arn:b", Region: "us-east-1"},
		{Name: "saml2sts-a", CredentialProcess: "saml2sts creds --role arn:a"},
	}
	ch, err := Sync(path, profiles, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Written) != 2 || len(ch.Removed) != 1 || ch.Removed[0] != "saml2sts-gone" {
		t.Errorf("Change = %+v", ch)
	}
	got, _ := os.ReadFile(path)
	const want = `# my settings
[default]
region = ap-northeast-1

# work account
[profile work]
region = us-west-2

[profile saml2sts-a]
# managed by saml2sts profiles sync
credential_process = saml2sts creds --role arn:a

[profile saml2sts-b]
# managed by saml2sts profiles sync
credential_process = saml2sts creds --role arn:b
region = us-east-1
`
	if string(got) != want {
		t.Errorf("file =\n%s\nwant\n%s", got, want)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want 0644 kept", fi.Mode().Perm())
	}

	// A second sync with the same profiles changes nothing.
	if _, err := Sync(path, profiles, false); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(path); string(again) != want {
		t.Errorf("second sync changed the file:\n%s", again)
	}
	if !Has(path, "saml2sts-a") || Has(path, "saml2sts-gone") {
		t.Error("Has disagrees with the file")
	}
}

func TestSyncDryRunAndNewFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aws", "config")
	p := []Profile{{Name: "saml2sts-a", CredentialProcess: "saml2sts creds --role arn:a"}}
	if _, err := Sync(path, p, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("dry run wrote the file")
	}
	if _, err := Sync(path, p, false); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "[profile saml2sts-a]\n# managed by saml2sts profiles sync\ncredential_process = saml2sts creds --role arn:a\n" {
		t.Errorf("new file =\n%s", got)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("new file mode = %v", fi.Mode().Perm())
	}
}

func TestSyncRejectsInjection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	for _, p := range []Profile{
		{Name: "saml2sts-a]\n[profile b", CredentialProcess: "saml2sts creds"},
		{Name: "saml2sts-a b", CredentialProcess: "saml2sts creds"},
		{Name: "saml2sts-a", CredentialProcess: "saml2sts creds --role x\ncredential_process = evil"},
		{Name: "saml2sts-a", CredentialProcess: "saml2sts creds", Region: "us-east-1\r"},
		{Name: "saml2sts-a", CredentialProcess: "saml2sts creds", EndpointURL: "http://x\x1b[0m"},
	} {
		if _, err := Sync(path, []Profile{p}, false); err == nil {
			t.Errorf("Sync accepted %+v", p)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("Sync wrote the file: %v", err)
	}
}
