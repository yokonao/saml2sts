//go:build !darwin

package main

import (
	"github.com/spf13/cobra"

	"github.com/yokonao/saml2sts/internal/agent"
	"github.com/yokonao/saml2sts/internal/federation"
)

// runBrowserHost does nothing: a browser runs only on the sign-in machine,
// which is a Mac.
func runBrowserHost([]string) (bool, error) { return false, nil }

// subcommands are those of a work machine, which gets everything from the
// agent on the sign-in machine.
func subcommands() []*cobra.Command {
	return []*cobra.Command{newCredsCmd(), newExecCmd(), newRolesCmd()}
}

type roleFlags struct {
	role string
}

func (f *roleFlags) register(cmd *cobra.Command, roleRequired bool) {
	cmd.Flags().StringVarP(&f.role, "role", "r", "", "role ARN, or a name from [roles] in the config file of the agent")
	if roleRequired {
		_ = cmd.MarkFlagRequired("role")
	}
}

func (f *roleFlags) fetch(cmd *cobra.Command) (federation.Credentials, string, error) {
	sock, err := agent.Socket()
	if err != nil {
		return federation.Credentials{}, "", err
	}
	return agent.Credentials(cmd.Context(), sock, f.role)
}

func availableRoles(cmd *cobra.Command) ([]agent.Role, error) {
	sock, err := agent.Socket()
	if err != nil {
		return nil, err
	}
	return agent.Roles(cmd.Context(), sock)
}
