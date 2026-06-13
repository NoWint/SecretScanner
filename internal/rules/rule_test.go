package rules

import "testing"

func TestRuleHasRequiredFields(t *testing.T) {
	r := Rule{
		ID:         "test-rule",
		Name:       "Test Rule",
		Pattern:    `AKIA[0-9A-Z]{16}`,
		EntropyMin: 0,
		Severity:   "high",
		Keywords:   []string{"AKIA"},
	}
	if r.ID != "test-rule" {
		t.Errorf("expected ID test-rule, got %s", r.ID)
	}
	if r.Severity != "high" {
		t.Errorf("expected severity high, got %s", r.Severity)
	}
}

func TestFindingHasRequiredFields(t *testing.T) {
	f := Finding{
		RuleID:     "aws-access-key",
		RuleName:   "AWS Access Key ID",
		Severity:   "high",
		FilePath:   "config.go",
		LineNumber: 42,
		Match:      "AKIAIOSFODNN7EXAMPLE",
		Entropy:    4.72,
		CommitHash: "a1b2c3d",
	}
	if f.RuleID != "aws-access-key" {
		t.Errorf("expected RuleID aws-access-key, got %s", f.RuleID)
	}
	if f.Entropy != 4.72 {
		t.Errorf("expected Entropy 4.72, got %f", f.Entropy)
	}
}
