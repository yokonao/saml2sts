package main

import (
	"encoding/json"
	"time"

	"github.com/spf13/cobra"
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
	var f roleFlags
	cmd := &cobra.Command{
		Use:   "creds",
		Short: "Print credentials for credential_process, from the cache, a sign-in or the agent",
		Example: `  # ~/.aws/config
  [profile prod]
  credential_process = saml2sts creds --role prod-admin`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, _, err := f.fetch(cmd)
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
