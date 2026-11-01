//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"regexp"
)

// defaultHostName is a variable so that a build can set its own with
// -ldflags "-X main.defaultHostName=...".
var defaultHostName = "io.github.yokonao.saml2sts"

type browser struct {
	// dir is the browser's directory under ~/Library/Application Support.
	dir string
	// systemDir holds the machine-wide NativeMessagingHosts; empty when the
	// browser has none we know of.
	systemDir string
	// profiles is the directory under ~/Library/Application Support that
	// holds the browser's profiles, when it is not dir.
	profiles string
	firefox  bool
}

var browsers = map[string]browser{
	"chrome":      {dir: "Google/Chrome", systemDir: "/Library/Google/Chrome"},
	"chrome-beta": {dir: "Google/Chrome Beta", systemDir: "/Library/Google/Chrome"},
	"chromium":    {dir: "Chromium", systemDir: "/Library/Application Support/Chromium"},
	"brave":       {dir: "BraveSoftware/Brave-Browser"},
	"edge":        {dir: "Microsoft Edge", systemDir: "/Library/Microsoft/Edge"},
	"firefox":     {dir: "Mozilla", systemDir: "/Library/Application Support/Mozilla", profiles: "Firefox/Profiles", firefox: true},
}

// firefoxID matches Firefox add-on IDs, which are email-like or a braced UUID.
var firefoxID = regexp.MustCompile(`^([A-Za-z0-9._+-]*@[A-Za-z0-9._-]+|\{[0-9A-Fa-f-]{36}\})$`)

// systemRoot prefixes the machine-wide directories, for tests.
var systemRoot = "/"

type hostManifest struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Path              string   `json:"path"`
	Type              string   `json:"type"`
	AllowedOrigins    []string `json:"allowed_origins,omitempty"`
	AllowedExtensions []string `json:"allowed_extensions,omitempty"`
}

func appSupport() (string, error) {
	home, err := os.UserHomeDir()
	return filepath.Join(home, "Library", "Application Support"), err
}
