package hook

import (
	"fmt"
	"os"
	"path/filepath"
)

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

	// Resolve the absolute path of the secretscanner binary
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolving executable path: %w", err)
	}
	execPath, err = filepath.Abs(execPath)
	if err != nil {
		return fmt.Errorf("resolving absolute path: %w", err)
	}

	hookContent := fmt.Sprintf(`#!/bin/sh
# SecretScanner pre-commit hook
# Scans staged files for secrets before allowing commit
%s scan --staged --no-history --format=table
exit $?
`, execPath)

	if err := os.WriteFile(hookPath, []byte(hookContent), 0755); err != nil {
		return fmt.Errorf("writing hook file: %w", err)
	}

	fmt.Printf("Pre-commit hook installed at %s\n", hookPath)
	return nil
}
