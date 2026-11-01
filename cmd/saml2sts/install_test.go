package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestInstall(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cmd := newRootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetArgs([]string{"install", "--browser", "chrome,firefox", "--path", "/bin/saml2sts",
		"--extension-id", "ljanpcedhfnidohflcgdjflhhjebpikb", "--extension-id", "saml2sts@yokonao.github.io"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	read := func(dir string) hostManifest {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(home, "Library/Application Support", dir, "NativeMessagingHosts", defaultHostName+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var m hostManifest
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if m := read("Google/Chrome"); !slices.Equal(m.AllowedOrigins, []string{"chrome-extension://ljanpcedhfnidohflcgdjflhhjebpikb/"}) || m.AllowedExtensions != nil {
		t.Errorf("chrome manifest = %+v", m)
	}
	if m := read("Mozilla"); !slices.Equal(m.AllowedExtensions, []string{"saml2sts@yokonao.github.io"}) || m.AllowedOrigins != nil {
		t.Errorf("firefox manifest = %+v", m)
	}
}

func TestInstallNeedsIDForEachBrowser(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cmd := newRootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"install", "--browser", "firefox", "--extension-id", "ljanpcedhfnidohflcgdjflhhjebpikb"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for Firefox without a Firefox extension ID")
	}
}

func TestInstallRejectsBadNameOrPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, args := range [][]string{
		{"--name", "../evil"},
		{"--name", "Io.Example"},
		{"--path", "bin/saml2sts"},
	} {
		cmd := newRootCmd()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(append([]string{"install", "--extension-id", "ljanpcedhfnidohflcgdjflhhjebpikb", "--path", "/bin/saml2sts"}, args...))
		if err := cmd.Execute(); err == nil {
			t.Errorf("install %q succeeded", args)
		}
	}
}

func runInstall(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(append([]string{"install"}, args...))
	err := cmd.Execute()
	return out.String(), err
}

func TestInstallSystem(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir()
	old := systemRoot
	systemRoot = root
	t.Cleanup(func() { systemRoot = old })

	if _, err := runInstall(t, "--system", "--path", filepath.Join(t.TempDir(), "saml2sts"), "--extension-id", "ljanpcedhfnidohflcgdjflhhjebpikb"); err == nil {
		t.Error("--system accepted a binary the user can replace")
	}
	if _, err := runInstall(t, "--system", "--browser", "brave", "--path", "/usr/bin/true", "--extension-id", "ljanpcedhfnidohflcgdjflhhjebpikb"); err == nil {
		t.Error("--system accepted a browser without a known machine-wide location")
	}
	out, err := runInstall(t, "--system", "--browser", "chrome,chrome-beta,firefox", "--path", "/usr/bin/true",
		"--extension-id", "ljanpcedhfnidohflcgdjflhhjebpikb", "--extension-id", "saml2sts@yokonao.github.io")
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"Library/Google/Chrome", "Library/Application Support/Mozilla"} {
		if _, err := os.Stat(filepath.Join(root, dir, "NativeMessagingHosts", defaultHostName+".json")); err != nil {
			t.Error(err)
		}
	}
	if n := strings.Count(out, "wrote "); n != 2 {
		t.Errorf("wrote %d manifests, want Chrome's shared with Chrome Beta and Firefox's:\n%s", n, out)
	}
}

func TestInstallPrint(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	out, err := runInstall(t, "--print", "--browser", "firefox", "--path", "/bin/saml2sts", "--extension-id", "saml2sts@yokonao.github.io")
	if err != nil {
		t.Fatal(err)
	}
	var m hostManifest
	if err := json.Unmarshal([]byte(out), &m); err != nil || m.Path != "/bin/saml2sts" || !slices.Equal(m.AllowedExtensions, []string{"saml2sts@yokonao.github.io"}) {
		t.Errorf("printed %q: %v", out, err)
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Error("--print wrote files")
	}
	if _, err := runInstall(t, "--print", "--browser", "chrome,firefox", "--path", "/bin/saml2sts",
		"--extension-id", "ljanpcedhfnidohflcgdjflhhjebpikb", "--extension-id", "saml2sts@yokonao.github.io"); err == nil {
		t.Error("--print accepted two browsers")
	}
}
