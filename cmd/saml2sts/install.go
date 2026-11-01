//go:build darwin

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/yokonao/saml2sts/internal/rootowned"
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

// systemRoot prefixes the machine-wide directories, for tests.
var systemRoot = "/"

var (
	chromiumID = regexp.MustCompile(`^[a-p]{32}$`)
	// Firefox add-on IDs are email-like or a braced UUID.
	firefoxID = regexp.MustCompile(`^([A-Za-z0-9._+-]*@[A-Za-z0-9._-]+|\{[0-9A-Fa-f-]{36}\})$`)
	// hostName is the rule browsers apply to native messaging host names.
	hostName = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)*$`)
)

type hostManifest struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Path              string   `json:"path"`
	Type              string   `json:"type"`
	AllowedOrigins    []string `json:"allowed_origins,omitempty"`
	AllowedExtensions []string `json:"allowed_extensions,omitempty"`
}

type installFlags struct {
	ids     []string
	names   []string
	name    string
	path    string
	dataDir string
	system  bool
	print   bool
}

func newInstallCmd() *cobra.Command {
	var f installFlags
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Register this binary as the native messaging host of the browser extension",
		Long: "Register this binary as the native messaging host of the browser extension, for the current user, " +
			"or with --system for every user of the machine. --print writes the manifest to stdout instead, " +
			"for a device management tool to place.",
		Example: `  saml2sts install --browser chrome,firefox \
    --extension-id ljanpcedhfnidohflcgdjflhhjebpikb --extension-id saml2sts@yokonao.github.io
  sudo saml2sts install --system --path /usr/local/bin/saml2sts --extension-id ljanpcedhfnidohflcgdjflhhjebpikb`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			targets, err := f.targets()
			if err != nil {
				return err
			}
			if f.print {
				if len(targets) != 1 {
					return errors.New("--print writes one manifest; pass one --browser")
				}
				b, err := json.MarshalIndent(targets[0].m, "", "  ")
				if err != nil {
					return err
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", b)
				return err
			}
			for _, t := range targets {
				file, err := t.write(f.name)
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", file)
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&f.ids, "extension-id", nil, "ID of an extension allowed to call the host, Chromium or Firefox (repeatable)")
	cmd.Flags().StringSliceVar(&f.names, "browser", []string{"chrome"}, "browsers to register with")
	cmd.Flags().StringVar(&f.name, "name", defaultHostName, "native messaging host name the extension connects to")
	cmd.Flags().StringVar(&f.path, "path", "", "host binary path (default: this binary)")
	cmd.Flags().StringVar(&f.dataDir, "user-data-dir", "", "register with the Chromium browser run with this --user-data-dir instead of --browser")
	cmd.Flags().BoolVar(&f.system, "system", false, "register for every user, in the machine-wide directories; the binary must be in a root-owned path")
	cmd.Flags().BoolVar(&f.print, "print", false, "write the manifest to stdout instead of registering it")
	cmd.MarkFlagsMutuallyExclusive("system", "user-data-dir")
	_ = cmd.MarkFlagRequired("extension-id")
	return cmd
}

type installTarget struct {
	// dir holds NativeMessagingHosts.
	dir string
	m   hostManifest
}

func (t installTarget) write(name string) (string, error) {
	b, err := json.MarshalIndent(t.m, "", "  ")
	if err != nil {
		return "", err
	}
	dir := filepath.Join(t.dir, "NativeMessagingHosts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	file := filepath.Join(dir, name+".json")
	return file, os.WriteFile(file, append(b, '\n'), 0o644)
}

func (f installFlags) targets() ([]installTarget, error) {
	var origins, geckoIDs []string
	for _, id := range f.ids {
		switch {
		case chromiumID.MatchString(id):
			origins = append(origins, "chrome-extension://"+id+"/")
		case firefoxID.MatchString(id):
			geckoIDs = append(geckoIDs, id)
		default:
			return nil, fmt.Errorf("%q is neither a Chromium nor a Firefox extension ID", id)
		}
	}
	if !hostName.MatchString(f.name) {
		return nil, fmt.Errorf("--name %q must be dot-separated parts of a-z, 0-9 and _", f.name)
	}
	path := f.path
	if path == "" {
		// Not resolved through symlinks, which would pin the
		// version-specific path a package manager links to.
		exe, err := os.Executable()
		if err != nil {
			return nil, err
		}
		path = exe
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("--path %q must be absolute, as browsers require", path)
	}
	if f.system {
		// Otherwise a program running as a user could replace the binary
		// every user's browser starts.
		if err := rootowned.Check(path); err != nil {
			return nil, fmt.Errorf("--system needs a binary only root can change: %w", err)
		}
	}
	base := hostManifest{Name: f.name, Description: "saml2sts", Path: path, Type: "stdio"}
	chromium := base
	chromium.AllowedOrigins = origins

	var targets []installTarget
	if f.dataDir != "" {
		targets = append(targets, installTarget{f.dataDir, chromium})
	} else {
		support, err := appSupport()
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		for _, n := range f.names {
			b, ok := browsers[n]
			if !ok {
				return nil, fmt.Errorf("unknown browser %q (one of %s)", n, strings.Join(slices.Sorted(maps.Keys(browsers)), ", "))
			}
			m := chromium
			if b.firefox {
				m = base
				m.AllowedExtensions = geckoIDs
			}
			dir := filepath.Join(support, b.dir)
			if f.system {
				if b.systemDir == "" {
					return nil, fmt.Errorf("no machine-wide location known for %s; place the manifest from --print yourself", n)
				}
				dir = filepath.Join(systemRoot, b.systemDir)
			}
			// Chrome and Chrome Beta share the machine-wide directory.
			if !seen[dir] {
				seen[dir] = true
				targets = append(targets, installTarget{dir, m})
			}
		}
	}
	for _, t := range targets {
		if len(t.m.AllowedOrigins)+len(t.m.AllowedExtensions) == 0 {
			return nil, fmt.Errorf("no extension ID for %s", t.dir)
		}
	}
	return targets, nil
}

func appSupport() (string, error) {
	home, err := os.UserHomeDir()
	return filepath.Join(home, "Library", "Application Support"), err
}
