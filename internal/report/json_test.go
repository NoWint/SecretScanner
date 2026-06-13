package report

import (
	"encoding/json"
	"testing"

	"github.com/NoWint/SecretScanner/internal/rules"
)

func TestFormatJSONOutput(t *testing.T) {
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
	output := FormatJSON(findings, "/path/to/repo")

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if result["total_findings"].(float64) != 1 {
		t.Errorf("expected total_findings 1, got %v", result["total_findings"])
	}
	findingsArr := result["findings"].([]interface{})
	if len(findingsArr) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findingsArr))
	}
	f := findingsArr[0].(map[string]interface{})
	if f["rule_id"] != "aws-access-key" {
		t.Errorf("expected rule_id aws-access-key, got %v", f["rule_id"])
	}
}

func TestFormatJSONEmpty(t *testing.T) {
	output := FormatJSON(nil, "/path/to/repo")
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if result["total_findings"].(float64) != 0 {
		t.Errorf("expected total_findings 0, got %v", result["total_findings"])
	}
}
