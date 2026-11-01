// Package awsconfig writes the saml2sts-* profiles of the AWS config file and
// leaves every other line of it as it was.
package awsconfig

import (
	"bytes"
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Prefix starts the name of every profile saml2sts manages.
const Prefix = "saml2sts-"

// marker sits inside each managed section. It is not what marks a section as
// managed, the name prefix is, but tells a reader where it came from.
const marker = "# managed by saml2sts profiles sync"

// Profile is one profile to write.
type Profile struct {
	Name              string
	CredentialProcess string
	Region            string
	EndpointURL       string
}

func (p Profile) section() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[profile %s]\n%s\ncredential_process = %s\n", p.Name, marker, p.CredentialProcess)
	if p.Region != "" {
		fmt.Fprintf(&b, "region = %s\n", p.Region)
	}
	if p.EndpointURL != "" {
		fmt.Fprintf(&b, "endpoint_url = %s\n", p.EndpointURL)
	}
	return b.String()
}

// Path returns the AWS config file path; $AWS_CONFIG_FILE overrides it.
func Path() (string, error) {
	if p := os.Getenv("AWS_CONFIG_FILE"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".aws", "config"), nil
}

// ProfileName names the profile of a role: Prefix and its short name from
// the saml2sts config when it has one, else Prefix, the account and the role.
func ProfileName(alias, roleARN string) string {
	if alias != "" {
		return Prefix + alias
	}
	account, role := splitRoleARN(roleARN)
	return Prefix + account + "-" + strings.ReplaceAll(role, "/", "-")
}

var roleARN = regexp.MustCompile(`^arn:[^:]+:iam::([0-9]{12}):role/(.+)$`)

func splitRoleARN(arn string) (account, role string) {
	m := roleARN.FindStringSubmatch(arn)
	if m == nil {
		return "unknown", arn
	}
	return m[1], m[2]
}

// Change is what Sync did or, with dryRun, would do.
type Change struct {
	Written []string
	Removed []string
}

// Sync makes the saml2sts-* profiles of the file at path exactly profiles.
func Sync(path string, profiles []Profile, dryRun bool) (Change, error) {
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return Change{}, err
	}
	kept, removed := splitManaged(string(old))
	var ch Change
	var b strings.Builder
	b.WriteString(kept)
	if kept != "" && !strings.HasSuffix(kept, "\n\n") {
		b.WriteString(strings.Repeat("\n", 2-trailingNewlines(kept)))
	}
	slices.SortFunc(profiles, func(a, b Profile) int { return cmp.Compare(a.Name, b.Name) })
	for i, p := range profiles {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(p.section())
		ch.Written = append(ch.Written, p.Name)
	}
	for _, name := range removed {
		if !slices.Contains(ch.Written, name) {
			ch.Removed = append(ch.Removed, name)
		}
	}
	if dryRun || bytes.Equal(old, []byte(b.String())) {
		return ch, nil
	}
	return ch, writeAtomic(path, []byte(b.String()))
}

// Has reports whether the file at path has a profile called name.
func Has(path, name string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if n, ok := profileHeader(line); ok && n == name {
			return true
		}
	}
	return false
}

// splitManaged drops the saml2sts-* sections from an INI file and returns the
// rest unchanged with the names it dropped. Comments and blank lines at the
// end of a dropped section stay, since they introduce the section after it.
func splitManaged(s string) (string, []string) {
	var kept strings.Builder
	var removed, trailing []string
	skipping := false
	for _, line := range strings.SplitAfter(s, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "["):
			name, ok := profileHeader(line)
			managed := ok && strings.HasPrefix(name, Prefix)
			if skipping && !managed {
				for len(trailing) > 0 && strings.TrimSpace(trailing[0]) == "" && strings.HasSuffix(kept.String(), "\n\n") {
					trailing = trailing[1:]
				}
				kept.WriteString(strings.Join(trailing, ""))
			}
			trailing = nil
			skipping = managed
			if managed {
				removed = append(removed, name)
				continue
			}
		case skipping && (t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";")):
			trailing = append(trailing, line)
			continue
		case skipping:
			trailing = nil
			continue
		}
		kept.WriteString(line)
	}
	return strings.TrimRight(kept.String(), "\n") + newlineIfAny(kept.String()), removed
}

func profileHeader(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "[") || !strings.HasSuffix(t, "]") {
		return "", false
	}
	name, ok := strings.CutPrefix(strings.TrimSpace(t[1:len(t)-1]), "profile ")
	return strings.TrimSpace(name), ok
}

func newlineIfAny(s string) string {
	if strings.TrimRight(s, "\n") == "" {
		return ""
	}
	return "\n"
}

func trailingNewlines(s string) int {
	return len(s) - len(strings.TrimRight(s, "\n"))
}

func writeAtomic(path string, data []byte) error {
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".config-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
