package main

import (
	"encoding/json"
	"time"

	"github.com/spf13/cobra"

	"github.com/yokonao/saml2sts/internal/config"
)

// processOutput is the credential_process output format.
type processOutput struct {
	Version         int
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string
	SessionToken    string
	Expiration      string
}

func newCredsCmd() *cobra.Command {
	var f loginFlags
	cmd := &cobra.Command{
		Use:   "creds",
		Short: "Print credentials for credential_process, signing in when the cache has none",
		Example: `  # ~/.aws/config
  [profile prod]
  credential_process = saml2sts creds --role prod-admin`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			c, _, err := f.credentials(cmd, cfg, false, nil)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(processOutput{
				Version:         1,
				AccessKeyID:     c.AccessKeyID,
				SecretAccessKey: c.SecretAccessKey,
				SessionToken:    c.SessionToken,
				Expiration:      c.Expiration.UTC().Format(time.RFC3339),
			})
		},
	}
	f.register(cmd, true)
	return cmd
}
