//go:build darwin

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/yokonao/saml2sts/internal/config"
	"github.com/yokonao/saml2sts/internal/keychain"
	"github.com/yokonao/saml2sts/internal/store"
)

// report prints check results and counts the failures.
type report struct {
	w        io.Writer
	failures int
}

func (r *report) section(name string) { _, _ = fmt.Fprintf(r.w, "%s\n", name) }

func (r *report) line(status, msg, fix string) {
	_, _ = fmt.Fprintf(r.w, "  %-4s  %s\n", status, msg)
	if fix != "" {
		_, _ = fmt.Fprintf(r.w, "        fix: %s\n", fix)
	}
}

func (r *report) ok(format string, args ...any) { r.line("ok", fmt.Sprintf(format, args...), "") }

func (r *report) warn(fix, format string, args ...any) {
	r.line("warn", fmt.Sprintf(format, args...), fix)
}

func (r *report) fail(fix, format string, args ...any) {
	r.failures++
	r.line("FAIL", fmt.Sprintf(format, args...), fix)
}

func newDoctorCmd() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check the setup of saml2sts without signing in",
		Long: "Check the config files, the native messaging host manifests, the browser extension, the code signature " +
			"and Keychain access, and print what to fix. It exits non-zero when a check fails.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := &report{w: cmd.OutOrStdout()}
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			checkConfig(r)
			ids := checkManifests(r, name, exe)
			checkExtensions(r, ids)
			checkSignature(r, exe)
			checkKeychain(r)
			if r.failures > 0 {
				return fmt.Errorf("%d check(s) failed", r.failures)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", defaultHostName, "native messaging host name the extension connects to")
	return cmd
}

func checkConfig(r *report) {
	r.section("config")
	files, err := config.Files()
	if err != nil {
		r.fail("", "%v", err)
		return
	}
	for _, f := range files {
		kind := "user"
		if f == config.SystemPath {
			kind = "system"
		}
		r.ok("%s config %s", kind, f)
	}
	c, err := config.Load()
	if err != nil {
		user, _ := config.Path()
		r.fail("write [idp] url to "+user+", or fix the error", "%v", err)
		return
	}
	from := func(key string) string {
		if src, ok := c.Sources[key]; ok {
			return "from " + src
		}
		return "default"
	}
	r.ok("idp.url = %s (%s)", c.IDP.URL, from("idp.url"))
	endpoint := c.IDP.STSEndpoint
	if endpoint == "" {
		endpoint = "regional STS endpoint"
	}
	r.ok("idp.sts_endpoint = %s (%s)", endpoint, from("idp.sts_endpoint"))
	r.ok("idp.region = %s (%s)", c.IDP.Region, from("idp.region"))
	if _, ok := c.Sources["idp.sts_endpoint"]; ok && c.Sources["idp.sts_endpoint"] != config.SystemPath && c.IDP.STSEndpoint != "" {
		r.warn("check that you set it; the native messaging host sends SAML responses there",
			"idp.sts_endpoint comes from a file any program running as you can change")
	}
}

type manifestLocation struct {
	browser string
	file    string
	system  bool
}

func manifestLocations(name string) ([]manifestLocation, error) {
	support, err := appSupport()
	if err != nil {
		return nil, err
	}
	var locs []manifestLocation
	for _, n := range slices.Sorted(maps.Keys(browsers)) {
		b := browsers[n]
		locs = append(locs, manifestLocation{n, filepath.Join(support, b.dir, "NativeMessagingHosts", name+".json"), false})
		if b.systemDir != "" {
			locs = append(locs, manifestLocation{n, filepath.Join(systemRoot, b.systemDir, "NativeMessagingHosts", name+".json"), true})
		}
	}
	return locs, nil
}

// checkManifests returns the allowed extension IDs per browser.
func checkManifests(r *report, name, exe string) map[string][]string {
	r.section("native messaging host " + name)
	locs, err := manifestLocations(name)
	if err != nil {
		r.fail("", "%v", err)
		return nil
	}
	ids := map[string][]string{}
	found := false
	for _, l := range locs {
		b, err := os.ReadFile(l.file)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		found = true
		scope := "user"
		if l.system {
			scope = "system"
		}
		label := fmt.Sprintf("%s (%s) %s", l.browser, scope, l.file)
		if err != nil {
			r.fail("", "%s: %v", label, err)
			continue
		}
		var m hostManifest
		if err := json.Unmarshal(b, &m); err != nil {
			r.fail("run saml2sts install again", "%s: %v", label, err)
			continue
		}
		allowed := append(slices.Clone(m.AllowedExtensions), m.AllowedOrigins...)
		for _, o := range m.AllowedOrigins {
			ids[l.browser] = append(ids[l.browser], strings.TrimSuffix(strings.TrimPrefix(o, "chrome-extension://"), "/"))
		}
		ids[l.browser] = append(ids[l.browser], m.AllowedExtensions...)
		fi, err := os.Stat(m.Path)
		switch {
		case err != nil:
			r.fail("run saml2sts install again from the binary you use", "%s: binary %s: %v", label, m.Path, err)
		case !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0:
			r.fail("make "+m.Path+" executable, or run saml2sts install again", "%s: %s is not an executable file", label, m.Path)
		case len(allowed) == 0:
			r.fail("run saml2sts install with --extension-id", "%s: no extension is allowed", label)
		default:
			r.ok("%s -> %s, allows %s", label, m.Path, strings.Join(allowed, ", "))
			if !sameFile(m.Path, exe) {
				r.warn("run the CLI from "+m.Path+", or install this binary",
					"%s: the host is not this binary (%s); Keychain items trust only the binary that wrote them", l.browser, exe)
			}
		}
	}
	if !found {
		r.fail("run saml2sts install --extension-id <ID>", "no host manifest for any browser")
	}
	return ids
}

func sameFile(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	return err == nil && os.SameFile(fa, fb)
}

func checkExtensions(r *report, ids map[string][]string) {
	r.section("browser extension")
	support, err := appSupport()
	if err != nil {
		r.fail("", "%v", err)
		return
	}
	for _, n := range slices.Sorted(maps.Keys(ids)) {
		b := browsers[n]
		dir := filepath.Join(support, b.dir)
		if b.profiles != "" {
			dir = filepath.Join(support, b.profiles)
		}
		installed := installedExtensions(dir, b.firefox)
		var hits []string
		for _, id := range ids[n] {
			for _, profile := range slices.Sorted(maps.Keys(installed)) {
				if installed[profile][id] {
					hits = append(hits, fmt.Sprintf("%s in %s", id, profile))
				}
			}
		}
		if len(hits) > 0 {
			r.ok("%s: %s", n, strings.Join(hits, ", "))
			continue
		}
		r.warn("install the extension with one of the allowed IDs, or pass its ID to saml2sts install",
			"%s: no profile has an allowed extension (%s); a temporary add-on does not show here", n, strings.Join(ids[n], ", "))
	}
}

// installedExtensions maps each profile under dir to the IDs of its extensions.
func installedExtensions(dir string, firefox bool) map[string]map[string]bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := map[string]map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		ids := map[string]bool{}
		if firefox {
			var f struct {
				Addons []struct {
					ID string `json:"id"`
				} `json:"addons"`
			}
			if b, err := os.ReadFile(filepath.Join(p, "extensions.json")); err == nil && json.Unmarshal(b, &f) == nil {
				for _, a := range f.Addons {
					ids[a.ID] = true
				}
			}
		} else {
			// Unpacked extensions are only in the preferences, not Extensions/.
			for _, file := range []string{"Preferences", "Secure Preferences"} {
				var prefs struct {
					Extensions struct {
						Settings map[string]json.RawMessage `json:"settings"`
					} `json:"extensions"`
				}
				if b, err := os.ReadFile(filepath.Join(p, file)); err == nil && json.Unmarshal(b, &prefs) == nil {
					for id := range prefs.Extensions.Settings {
						ids[id] = true
					}
				}
			}
		}
		if len(ids) > 0 {
			out[e.Name()] = ids
		}
	}
	return out
}

func checkSignature(r *report, exe string) {
	r.section("code signature")
	out, err := exec.Command("codesign", "-dv", "--verbose=2", exe).CombinedOutput()
	if err != nil {
		r.warn("sign it with a Developer ID, or expect macOS to ask for Keychain items after each upgrade",
			"%s is not signed: %s", exe, strings.TrimSpace(string(out)))
		return
	}
	var authority, team string
	adhoc := false
	for _, l := range strings.Split(string(out), "\n") {
		switch {
		case strings.HasPrefix(l, "Authority=") && authority == "":
			authority = strings.TrimPrefix(l, "Authority=")
		case strings.HasPrefix(l, "TeamIdentifier="):
			team = strings.TrimPrefix(l, "TeamIdentifier=")
		case l == "Signature=adhoc":
			adhoc = true
		}
	}
	if adhoc || authority == "" {
		r.warn("use a build signed with a Developer ID to keep Keychain access across upgrades",
			"%s has an ad-hoc signature; macOS asks again for Keychain items after each upgrade", exe)
		return
	}
	if err := exec.Command("codesign", "--verify", "--strict", exe).Run(); err != nil {
		r.fail("reinstall saml2sts", "%s: signature by %s does not verify: %v", exe, authority, err)
		return
	}
	r.ok("%s, team %s", authority, team)
}

func checkKeychain(r *report) {
	r.section("Keychain")
	n, errs := store.CheckAccess()
	for _, err := range errs {
		if errors.Is(err, keychain.ErrWouldPrompt) {
			r.fail("run saml2sts logout --all to drop items an older binary wrote, or allow access once at the prompt", "%v", err)
		} else {
			r.fail("", "%v", err)
		}
	}
	if len(errs) == 0 {
		r.ok("%d item(s) readable without a prompt", n)
	}
}
