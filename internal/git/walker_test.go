package git

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/NoWint/SecretScanner/internal/rules"
)

func TestScanRepositoryOnRealGitRepo(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")

	findings, err := ScanRepository(repoRoot, []rules.Rule{
		{
			ID:         "test-rule",
			Name:       "Test Rule",
			Pattern:    `AKIA[0-9A-Z]{16}`,
			EntropyMin: 0,
			Severity:   "high",
			Keywords:   []string{"AKIA"},
		},
	})
	if err != nil {
		t.Fatalf("ScanRepository returned error: %v", err)
	}
	if len(findings) < 0 {
		t.Errorf("unexpected negative findings count")
	}
}

func TestScanRepositoryInvalidPath(t *testing.T) {
	_, err := ScanRepository("/nonexistent/path", nil)
	if err == nil {
		t.Error("expected error for invalid path")
	}
}
