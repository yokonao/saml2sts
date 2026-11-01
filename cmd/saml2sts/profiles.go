package main

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/yokonao/saml2sts/internal/awsconfig"
	"github.com/yokonao/saml2sts/internal/config"
	"github.com/yokonao/saml2sts/internal/login"
	"github.com/yokonao/saml2sts/internal/saml"
	"github.com/yokonao/saml2sts/internal/store"
)

func newProfilesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profiles",
		Short: "Manage the AWS profiles saml2sts writes for your roles",
	}
	cmd.AddCommand(newProfilesSyncCmd())
	return cmd
}

func newProfilesSyncCmd() *cobra.Command {
	var (
		f           loginFlags
		refresh     bool
		dryRun      bool
		command     string
		region      string
		endpointURL string
	)
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Write an AWS profile to the AWS config file for each role of the last sign-in",
		Long: "Write an AWS profile to the AWS config file for each role your IdP allows, named by [profiles] in the config file or " + awsconfig.Prefix + "*, " +
			"and remove the profiles it wrote for roles no longer there. Other profiles are left alone. " +
			"With no roles from an earlier sign-in, or with --refresh, it signs in first to read them, assuming no role.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			var roles []saml.Role
			if !refresh {
				if roles, err = store.ReadRoles(); err != nil {
					return err
				}
			}
			if len(roles) == 0 {
				err := login.ListRoles(cmd.Context(), cfg, login.Options{
					NoOpen: f.noOpen, Timeout: f.timeout, Log: cmd.ErrOrStderr(),
				})
				if err != nil {
					return err
				}
				if roles, err = store.ReadRoles(); err != nil {
					return err
				}
			}
			path, err := awsconfig.Path()
			if err != nil {
				return err
			}
			var profiles []awsconfig.Profile
			allowed := map[string]bool{}
			for _, r := range roles {
				allowed[r.RoleARN] = true
				for _, name := range profileNames(cfg, r.RoleARN) {
					profiles = append(profiles, awsconfig.Profile{
						Name:              name,
						CredentialProcess: shellQuote(command) + " creds --role " + r.RoleARN,
						Region:            region,
						EndpointURL:       endpointURL,
					})
				}
			}
			for _, name := range slices.Sorted(maps.Keys(cfg.Profiles)) {
				if !allowed[cfg.Profiles[name]] {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "saml2sts: skipping [profiles] %s; your IdP does not allow %s\n", name, cfg.Profiles[name])
				}
			}
			ch, err := awsconfig.Sync(path, profiles, dryRun)
			if err != nil {
				return err
			}
			verb := "wrote"
			if dryRun {
				verb = "would write"
			}
			w := cmd.OutOrStdout()
			for _, n := range ch.Written {
				_, _ = fmt.Fprintf(w, "%s %s\n", verb, n)
			}
			for _, n := range ch.Removed {
				_, _ = fmt.Fprintf(w, "%s %s\n", strings.Replace(verb, "write", "remove", 1), n)
			}
			_, _ = fmt.Fprintf(w, "in %s\n", path)
			return nil
		},
	}
	cmd.Flags().BoolVar(&refresh, "refresh", false, "sign in to read the roles again")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show the changes without writing them")
	cmd.Flags().BoolVar(&f.noOpen, "no-open", false, "print the IdP URL instead of opening the browser")
	cmd.Flags().DurationVar(&f.timeout, "timeout", 5*time.Minute, "how long to wait for the browser sign-in")
	// An absolute path would break when a version manager moves the binary.
	cmd.Flags().StringVar(&command, "path", "saml2sts", "saml2sts command the profiles run")
	cmd.Flags().StringVar(&region, "region", "", "region to set in each profile")
	cmd.Flags().StringVar(&endpointURL, "endpoint-url", "", "endpoint_url to set in each profile, such as a local emulator")
	return cmd
}

// profileNames names the profiles of a role: those [profiles] gives it, or
// else the one awsconfig.ProfileName makes.
func profileNames(cfg config.Config, arn string) []string {
	if names := cfg.ProfileNames(arn); len(names) > 0 {
		return names
	}
	alias, _ := cfg.Alias(arn)
	return []string{awsconfig.ProfileName(alias, arn)}
}

var plainWord = regexp.MustCompile(`^[A-Za-z0-9_./:@-]+$`)

// shellQuote quotes s for the shell-like splitting of credential_process.
func shellQuote(s string) string {
	if plainWord.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
