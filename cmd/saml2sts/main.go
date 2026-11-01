package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if startedByBrowser(os.Args[1:]) {
		if err := runNativeHost(os.Stdin, os.Stdout); err != nil {
			os.Exit(1)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := newRootCmd().ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:     "saml2sts",
		Short:   "Get AWS credentials from a SAML sign-in in your browser",
		Version: version,
		// Usage would bury the error, and stdout may carry credential_process output.
		SilenceUsage: true,
	}
	root.AddCommand(newLoginCmd(), newCredsCmd(), newExecCmd(), newRolesCmd(), newProfilesCmd(), newLogoutCmd(), newInstallCmd())
	return root
}
