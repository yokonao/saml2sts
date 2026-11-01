package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
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
