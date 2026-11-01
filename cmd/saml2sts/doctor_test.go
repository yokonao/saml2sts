//go:build darwin

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yokonao/saml2sts/internal/config"
)

const chromeID = "ljanpcedhfnidohflcgdjflhhjebpikb"

func runDoctor(t *testing.T) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"doctor"})
	err := cmd.Execute()
	return out.String(), err
}

func setupDoctor(t *testing.T, hostPath string) string {
	t.Helper()
	useTestStore(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	old, oldRoot := config.SystemPath, systemRoot
	config.SystemPath, systemRoot = filepath.Join(home, "none.toml"), t.TempDir()
	t.Cleanup(func() { config.SystemPath, systemRoot = old, oldRoot })
	cfg := filepath.Join(home, "config.toml")
	if err := os.WriteFile(cfg, []byte("[idp]\nurl = \"https://idp.example.com/sso\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAML2STS_CONFIG", cfg)
	if _, err := runInstall(t, "--path", hostPath, "--extension-id", chromeID); err != nil {
		t.Fatal(err)
	}
	return home
}

func TestDoctor(t *testing.T) {
	home := setupDoctor(t, "/usr/bin/true")
	profile := filepath.Join(home, "Library/Application Support/Google/Chrome/Profile 1")
	if err := os.MkdirAll(profile, 0o700); err != nil {
		t.Fatal(err)
	}
	prefs := `{"extensions":{"settings":{"` + chromeID + `":{}}}}`
	if err := os.WriteFile(filepath.Join(profile, "Secure Preferences"), []byte(prefs), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runDoctor(t)
	if err != nil {
		t.Fatalf("doctor: %v\n%s", err, out)
	}
	for _, want := range []string{
		"idp.url = https://idp.example.com/sso (from ",
		"chrome (user) ",
		"-> /usr/bin/true, allows chrome-extension://" + chromeID + "/",
		"ok    chrome: " + chromeID + " in Profile 1",
		"readable without a prompt",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestDoctorFails(t *testing.T) {
	setupDoctor(t, "/nonexistent/saml2sts")
	out, err := runDoctor(t)
	if err == nil {
		t.Fatalf("doctor succeeded with a missing host binary:\n%s", out)
	}
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "fix: run saml2sts install again") {
		t.Errorf("output =\n%s", out)
	}
}
