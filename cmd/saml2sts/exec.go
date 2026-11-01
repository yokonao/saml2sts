package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/yokonao/saml2sts/internal/config"
)

func newExecCmd() *cobra.Command {
	var f loginFlags
	cmd := &cobra.Command{
		Use:   "exec --role <role> -- <command> [args...]",
		Short: "Run a command with credentials in its environment",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			c, roleARN, err := f.credentials(cmd, cfg, false, nil)
			if err != nil {
				return err
			}
			bin, err := exec.LookPath(args[0])
			if err != nil {
				return err
			}
			env := []string{
				"AWS_ACCESS_KEY_ID=" + c.AccessKeyID,
				"AWS_SECRET_ACCESS_KEY=" + c.SecretAccessKey,
				"AWS_SESSION_TOKEN=" + c.SessionToken,
				"AWS_CREDENTIAL_EXPIRATION=" + c.Expiration.UTC().Format("2006-01-02T15:04:05Z"),
				"SAML2STS_ROLE=" + roleARN,
			}
			for _, kv := range os.Environ() {
				// A profile would take precedence over the injected keys in some SDKs.
				if !strings.HasPrefix(kv, "AWS_PROFILE=") && !strings.HasPrefix(kv, "AWS_DEFAULT_PROFILE=") {
					env = append(env, kv)
				}
			}
			if err := syscall.Exec(bin, args, env); err != nil {
				return fmt.Errorf("exec %s: %w", args[0], err)
			}
			return nil
		},
	}
	f.register(cmd, true)
	return cmd
}
