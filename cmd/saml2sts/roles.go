package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newRolesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "roles",
		Short: "List the roles your IdP allowed at the last sign-in, or those the agent shares",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			roles, err := availableRoles(cmd)
			if err != nil {
				return err
			}
			for _, r := range roles {
				line := r.ARN
				if r.Name != "" {
					line = r.Name + "  " + r.ARN
				}
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), line); err != nil {
					return err
				}
			}
			return nil
		},
	}
}
