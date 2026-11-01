package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/yokonao/saml2sts/internal/config"
	"github.com/yokonao/saml2sts/internal/store"
)

func newRolesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "roles",
		Short: "List the roles your IdP allowed at the last sign-in",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			roles, err := store.ReadRoles()
			if err != nil {
				return err
			}
			if len(roles) == 0 {
				return fmt.Errorf("no roles yet; sign in once with saml2sts login")
			}
			for _, r := range roles {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), describeRole(cfg, r.RoleARN)); err != nil {
					return err
				}
			}
			return nil
		},
	}
}
