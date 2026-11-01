//go:build darwin

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yokonao/saml2sts/internal/config"
	"github.com/yokonao/saml2sts/internal/rootowned"
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

// writeManifest writes a Chrome host manifest into dir/NativeMessagingHosts.
func writeManifest(t *testing.T, dir, hostPath string) {
	t.Helper()
	b, err := json.Marshal(hostManifest{
		Name: defaultHostName, Description: "saml2sts", Path: hostPath, Type: "stdio",
		AllowedOrigins: []string{"chrome-extension://" + chromeID + "/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(dir, "NativeMessagingHosts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, defaultHostName+".json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// setupDoctor registers hostPath for Chrome, machine-wide when system.
func setupDoctor(t *testing.T, hostPath string, system bool) string {
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
	if system {
		writeManifest(t, filepath.Join(systemRoot, browsers["chrome"].systemDir), hostPath)
	} else {
		writeManifest(t, filepath.Join(home, "Library/Application Support", browsers["chrome"].dir), hostPath)
	}
	return home
}

func TestDoctor(t *testing.T) {
	home := setupDoctor(t, "/usr/bin/true", false)
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
		"chrome: a user-level manifest",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestDoctorFails(t *testing.T) {
	setupDoctor(t, "/nonexistent/saml2sts", false)
	out, err := runDoctor(t)
	if err == nil {
		t.Fatalf("doctor succeeded with a missing host binary:\n%s", out)
	}
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "fix: place the host manifest") {
		t.Errorf("output =\n%s", out)
	}
}

func TestDoctorSystemManifest(t *testing.T) {
	// The temporary directories stand in for root-owned ones.
	rootowned.Owners = []uint32{uint32(os.Getuid())}
	t.Cleanup(func() { rootowned.Owners = nil })

	setupDoctor(t, "/usr/bin/true", true)
	out, _ := runDoctor(t)
	if !strings.Contains(out, "ok    chrome (system) ") || strings.Contains(out, "user-level manifest") {
		t.Errorf("output =\n%s", out)
	}

	host := filepath.Join(t.TempDir(), "saml2sts")
	if err := os.WriteFile(host, nil, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(host, 0o777); err != nil {
		t.Fatal(err)
	}
	setupDoctor(t, host, true)
	out, err := runDoctor(t)
	if err == nil || !strings.Contains(out, "could replace the binary") {
		t.Errorf("doctor accepted a binary anyone can replace: %v\n%s", err, out)
	}
}
