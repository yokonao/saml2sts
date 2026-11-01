package main

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/yokonao/saml2sts/internal/awsconfig"
	"github.com/yokonao/saml2sts/internal/config"
	"github.com/yokonao/saml2sts/internal/federation"
	"github.com/yokonao/saml2sts/internal/login"
	"github.com/yokonao/saml2sts/internal/saml"
)

type loginFlags struct {
	role    string
	noOpen  bool
	timeout time.Duration
}

func (f *loginFlags) register(cmd *cobra.Command, roleRequired bool) {
	cmd.Flags().StringVarP(&f.role, "role", "r", "", "role ARN, or a name from [roles] in the config file")
	cmd.Flags().BoolVar(&f.noOpen, "no-open", false, "print the IdP URL instead of opening the browser")
	cmd.Flags().DurationVar(&f.timeout, "timeout", 5*time.Minute, "how long to wait for the browser sign-in")
	if roleRequired {
		_ = cmd.MarkFlagRequired("role")
	}
}

// credentials returns credentials and the ARN of their role. Without --role,
// choose picks a role after the sign-in.
func (f *loginFlags) credentials(cmd *cobra.Command, cfg config.Config, force bool, choose func([]saml.Role) (saml.Role, error)) (federation.Credentials, string, error) {
	var roleARN string
	if f.role != "" {
		var err error
		if roleARN, err = cfg.ResolveRole(f.role); err != nil {
			return federation.Credentials{}, "", err
		}
	}
	return login.Credentials(cmd.Context(), cfg, roleARN, login.Options{
		Force:   force,
		NoOpen:  f.noOpen,
		Timeout: f.timeout,
		Log:     cmd.ErrOrStderr(),
		Choose:  choose,
	})
}

func newLoginCmd() *cobra.Command {
	var f loginFlags
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in through the browser and cache the credentials of a role",
		Long:  "Sign in through the browser and cache the credentials of a role. Without --role, pick one of the roles your IdP allows after signing in.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			choose := func(roles []saml.Role) (saml.Role, error) {
				return chooseRole(cmd.InOrStdin(), cmd.ErrOrStderr(), cfg, roles)
			}
			c, roleARN, err := f.credentials(cmd, cfg, true, choose)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "saml2sts: credentials for %s valid until %s\n",
				cfg.RoleName(roleARN), c.Expiration.Local().Format(time.DateTime))
			profileHint(cmd.ErrOrStderr(), cfg, roleARN)
			return nil
		},
	}
	f.register(cmd, false)
	return cmd
}

// chooseRole asks on w for one of roles by number and reads the answer from r.
func chooseRole(r io.Reader, w io.Writer, cfg config.Config, roles []saml.Role) (saml.Role, error) {
	_, _ = fmt.Fprintln(w, "saml2sts: choose a role:")
	for i, role := range roles {
		_, _ = fmt.Fprintf(w, "  %d) %s\n", i+1, describeRole(cfg, role.RoleARN))
	}
	_, _ = fmt.Fprint(w, "> ")
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && line == "" {
		return saml.Role{}, fmt.Errorf("read the role: %w", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 1 || n > len(roles) {
		return saml.Role{}, fmt.Errorf("%q is not a number from 1 to %d", strings.TrimSpace(line), len(roles))
	}
	return roles[n-1], nil
}

// describeRole puts a role's name from [roles] in front of its ARN.
func describeRole(cfg config.Config, arn string) string {
	if name, ok := cfg.Alias(arn); ok {
		return name + "  " + arn
	}
	return arn
}

// profileHint tells how to use the role's credentials from the AWS CLI.
func profileHint(w io.Writer, cfg config.Config, arn string) {
	alias, _ := cfg.Alias(arn)
	name := awsconfig.ProfileName(alias, arn)
	path, err := awsconfig.Path()
	if err == nil && awsconfig.Has(path, name) {
		_, _ = fmt.Fprintf(w, "saml2sts: use them with aws --profile %s\n", name)
		return
	}
	_, _ = fmt.Fprintln(w, "saml2sts: run saml2sts profiles sync to add AWS profiles for your roles")
}
