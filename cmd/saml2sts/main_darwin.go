package main

import (
	"errors"
	"os"

	"github.com/spf13/cobra"

	"github.com/yokonao/saml2sts/internal/agent"
	"github.com/yokonao/saml2sts/internal/config"
	"github.com/yokonao/saml2sts/internal/federation"
	"github.com/yokonao/saml2sts/internal/store"
)

func runBrowserHost(args []string) (bool, error) {
	if !startedByBrowser(args) {
		return false, nil
	}
	return true, runNativeHost(os.Stdin, os.Stdout)
}

func subcommands() []*cobra.Command {
	return []*cobra.Command{newLoginCmd(), newCredsCmd(), newExecCmd(), newRolesCmd(), newProfilesCmd(), newLogoutCmd(), newDoctorCmd(), newAgentCmd()}
}

type roleFlags = loginFlags

// fetch asks the agent when $SAML2STS_AGENT_SOCK is set, as on a Mac that
// is a work machine, and otherwise reads the cache or signs in.
func (f *loginFlags) fetch(cmd *cobra.Command) (federation.Credentials, string, error) {
	if sock := os.Getenv(agent.SockEnv); sock != "" {
		return agent.Credentials(cmd.Context(), sock, f.role)
	}
	cfg, err := config.Load()
	if err != nil {
		return federation.Credentials{}, "", err
	}
	return f.credentials(cmd, cfg, false, nil)
}

func availableRoles(cmd *cobra.Command) ([]agent.Role, error) {
	if sock := os.Getenv(agent.SockEnv); sock != "" {
		return agent.Roles(cmd.Context(), sock)
	}
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	saved, err := store.ReadRoles()
	if err != nil {
		return nil, err
	}
	if len(saved) == 0 {
		return nil, errors.New("no roles yet; sign in once with saml2sts login")
	}
	roles := make([]agent.Role, len(saved))
	for i, r := range saved {
		name, _ := cfg.Alias(r.RoleARN)
		roles[i] = agent.Role{ARN: r.RoleARN, Name: name}
	}
	return roles, nil
}
