//go:build darwin

package main

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/yokonao/saml2sts/internal/config"
	"github.com/yokonao/saml2sts/internal/store"
)

func newLogoutCmd() *cobra.Command {
	var (
		role string
		all  bool
	)
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Delete the cached credentials of a role, or with --all of every role and the list of roles",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if all {
				return store.Forget()
			}
			if role == "" {
				return errors.New("give --role or --all")
			}
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			arn, err := cfg.ResolveRole(role)
			if err != nil {
				return err
			}
			return store.DeleteCache(arn)
		},
	}
	cmd.Flags().StringVarP(&role, "role", "r", "", "role ARN, or a name from [roles] in the config file")
	cmd.Flags().BoolVar(&all, "all", false, "delete the credentials of every role and the list of roles")
	cmd.MarkFlagsMutuallyExclusive("role", "all")
	return cmd
}
