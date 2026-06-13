package report

import (
	"strings"
	"testing"

	"github.com/NoWint/SecretScanner/internal/rules"
)

func TestFormatTableOutput(t *testing.T) {
	findings := []rules.Finding{
		{
			RuleID:     "aws-access-key",
			RuleName:   "AWS Access Key ID",
			Severity:   "high",
			FilePath:   "config.go",
			LineNumber: 42,
			Match:      "AKIA3E8F9Z7XMQ2P4L6",
			Entropy:    4.72,
			CommitHash: "a1b2c3d",
		},
	}
	output := FormatTable(findings)
	if !strings.Contains(output, "AWS Access Key ID") {
		t.Error("expected output to contain rule name")
	}
	if !strings.Contains(output, "config.go") {
		t.Error("expected output to contain file path")
	}
	if !strings.Contains(output, "HIGH") {
		t.Error("expected output to contain severity")
	}
}

func TestFormatTableEmpty(t *testing.T) {
	output := FormatTable(nil)
	if !strings.Contains(output, "0 secrets") {
		t.Error("expected output to indicate no secrets found")
	}
}

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"AKIA3E8F9Z7XMQ2P4L6", "AKIA3E...P4L6"},
		{"short", "short"},
		{"", ""},
	}
	for _, tt := range tests {
		got := MaskSecret(tt.input)
		if got != tt.expected {
			t.Errorf("MaskSecret(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
