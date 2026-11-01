package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

const defaultHostName = "io.github.yokonao.saml2sts"

type browser struct {
	// dir is the browser's directory under ~/Library/Application Support.
	dir     string
	firefox bool
}

var browsers = map[string]browser{
	"chrome":      {dir: "Google/Chrome"},
	"chrome-beta": {dir: "Google/Chrome Beta"},
	"chromium":    {dir: "Chromium"},
	"brave":       {dir: "BraveSoftware/Brave-Browser"},
	"edge":        {dir: "Microsoft Edge"},
	"firefox":     {dir: "Mozilla", firefox: true},
}

var (
	chromiumID = regexp.MustCompile(`^[a-p]{32}$`)
	// Firefox add-on IDs are email-like or a braced UUID.
	firefoxID = regexp.MustCompile(`^([A-Za-z0-9._+-]*@[A-Za-z0-9._-]+|\{[0-9A-Fa-f-]{36}\})$`)
)

type hostManifest struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Path              string   `json:"path"`
	Type              string   `json:"type"`
	AllowedOrigins    []string `json:"allowed_origins,omitempty"`
	AllowedExtensions []string `json:"allowed_extensions,omitempty"`
}

func newInstallCmd() *cobra.Command {
	var (
		ids     []string
		names   []string
		name    string
		path    string
		dataDir string
	)
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Register this binary as the native messaging host of the browser extension",
		Example: `  saml2sts install --browser chrome,firefox \
    --extension-id ljanpcedhfnidohflcgdjflhhjebpikb --extension-id saml2sts@yokonao.github.io`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var origins, geckoIDs []string
			for _, id := range ids {
				switch {
				case chromiumID.MatchString(id):
					origins = append(origins, "chrome-extension://"+id+"/")
				case firefoxID.MatchString(id):
					geckoIDs = append(geckoIDs, id)
				default:
					return fmt.Errorf("%q is neither a Chromium nor a Firefox extension ID", id)
				}
			}
			if path == "" {
				exe, err := os.Executable()
				if err != nil {
					return err
				}
				if path, err = filepath.EvalSymlinks(exe); err != nil {
					return err
				}
			}
			base := hostManifest{Name: name, Description: "saml2sts", Path: path, Type: "stdio"}

			type target struct {
				dir string
				m   hostManifest
			}
			var targets []target
			chromium := base
			chromium.AllowedOrigins = origins
			if dataDir != "" {
				targets = append(targets, target{dataDir, chromium})
			} else {
				support, err := appSupport()
				if err != nil {
					return err
				}
				for _, n := range names {
					b, ok := browsers[n]
					if !ok {
						return fmt.Errorf("unknown browser %q (one of %s)", n, strings.Join(slices.Sorted(maps.Keys(browsers)), ", "))
					}
					m := chromium
					if b.firefox {
						m = base
						m.AllowedExtensions = geckoIDs
					}
					targets = append(targets, target{filepath.Join(support, b.dir), m})
				}
			}

			for _, t := range targets {
				if len(t.m.AllowedOrigins)+len(t.m.AllowedExtensions) == 0 {
					return fmt.Errorf("no extension ID for %s", t.dir)
				}
				b, err := json.MarshalIndent(t.m, "", "  ")
				if err != nil {
					return err
				}
				dir := filepath.Join(t.dir, "NativeMessagingHosts")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					return err
				}
				file := filepath.Join(dir, name+".json")
				if err := os.WriteFile(file, append(b, '\n'), 0o644); err != nil {
					return err
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", file)
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&ids, "extension-id", nil, "ID of an extension allowed to call the host, Chromium or Firefox (repeatable)")
	cmd.Flags().StringSliceVar(&names, "browser", []string{"chrome"}, "browsers to register with")
	cmd.Flags().StringVar(&name, "name", defaultHostName, "native messaging host name the extension connects to")
	cmd.Flags().StringVar(&path, "path", "", "host binary path (default: this binary)")
	cmd.Flags().StringVar(&dataDir, "user-data-dir", "", "register with the Chromium browser run with this --user-data-dir instead of --browser")
	_ = cmd.MarkFlagRequired("extension-id")
	return cmd
}

func appSupport() (string, error) {
	home, err := os.UserHomeDir()
	return filepath.Join(home, "Library", "Application Support"), err
}
