package hook

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallHook(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatal(err)
	}

	err := InstallHook(dir)
	if err != nil {
		t.Fatalf("InstallHook returned error: %v", err)
	}

	hookPath := filepath.Join(gitDir, "pre-commit")
	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("failed to read hook file: %v", err)
	}
	if len(content) == 0 {
		t.Error("hook file is empty")
	}

	info, err := os.Stat(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&0111 == 0 {
		t.Error("hook file is not executable")
	}
}

func TestInstallHookNoGitDir(t *testing.T) {
	dir := t.TempDir()
	err := InstallHook(dir)
	if err == nil {
		t.Error("expected error when .git directory does not exist")
	}
}
