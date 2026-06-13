package hook

import (
	"fmt"
	"os"
	"path/filepath"
)

const hookContent = `#!/bin/sh
# SecretScanner pre-commit hook
# Scans staged files for secrets before allowing commit
secretscanner scan --staged --no-history --format=table
exit $?
`

// InstallHook installs the pre-commit hook in the given git repository.
func InstallHook(repoPath string) error {
	hooksDir := filepath.Join(repoPath, ".git", "hooks")
	if _, err := os.Stat(hooksDir); os.IsNotExist(err) {
		return fmt.Errorf("not a git repository: %s", repoPath)
	}

	hookPath := filepath.Join(hooksDir, "pre-commit")
	if _, err := os.Stat(hookPath); err == nil {
		return fmt.Errorf("pre-commit hook already exists at %s", hookPath)
	}

	if err := os.WriteFile(hookPath, []byte(hookContent), 0755); err != nil {
		return fmt.Errorf("writing hook file: %w", err)
	}

	fmt.Printf("Pre-commit hook installed at %s\n", hookPath)
	return nil
}
