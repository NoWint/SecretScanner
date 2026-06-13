package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/NoWint/SecretScanner/internal/hook"
)

var installHookCmd = &cobra.Command{
	Use:   "install-hook",
	Short: "Install pre-commit hook in the current repository",
	Long:  "Install a git pre-commit hook that scans staged files for secrets before allowing a commit.",
	Run: func(cmd *cobra.Command, args []string) {
		if err := hook.InstallHook("."); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
	},
}

func init() {
	rootCmd.AddCommand(installHookCmd)
}
