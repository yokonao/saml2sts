package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/yokonao/saml2sts/internal/federation"
)

func newExecCmd() *cobra.Command {
	var f roleFlags
	cmd := &cobra.Command{
		Use:   "exec --role <role> -- <command> [args...]",
		Short: "Run a command with credentials in its environment",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, roleARN, err := f.fetch(cmd)
			if err != nil {
				return err
			}
			bin, err := exec.LookPath(args[0])
			if err != nil {
				return err
			}
			env := execEnv(os.Environ(), c, roleARN)
			if err := syscall.Exec(bin, args, env); err != nil {
				return fmt.Errorf("exec %s: %w", args[0], err)
			}
			return nil
		},
	}
	f.register(cmd, true)
	return cmd
}

// execEnv replaces the credentials of parent with c. The keys must not
// appear twice, since programs differ on which one wins.
func execEnv(parent []string, c federation.Credentials, roleARN string) []string {
	var env []string
	for _, kv := range parent {
		k, _, _ := strings.Cut(kv, "=")
		switch k {
		// A profile would take precedence over the injected keys in some SDKs.
		case "AWS_PROFILE", "AWS_DEFAULT_PROFILE",
			"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
			"AWS_SECURITY_TOKEN", "AWS_CREDENTIAL_EXPIRATION", "SAML2STS_ROLE":
			continue
		}
		env = append(env, kv)
	}
	return append(env,
		"AWS_ACCESS_KEY_ID="+c.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY="+c.SecretAccessKey,
		"AWS_SESSION_TOKEN="+c.SessionToken,
		"AWS_CREDENTIAL_EXPIRATION="+c.Expiration.UTC().Format("2006-01-02T15:04:05Z"),
		"SAML2STS_ROLE="+roleARN,
	)
}
