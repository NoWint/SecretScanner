package rules

import "testing"

func TestBuiltinRulesNotEmpty(t *testing.T) {
	rules := BuiltinRules()
	if len(rules) == 0 {
		t.Error("expected non-empty builtin rules")
	}
}

func TestBuiltinRulesHaveRequiredFields(t *testing.T) {
	rules := BuiltinRules()
	for _, r := range rules {
		if r.ID == "" {
			t.Error("rule missing ID")
		}
		if r.Name == "" {
			t.Errorf("rule %s missing Name", r.ID)
		}
		if r.Pattern == "" {
			t.Errorf("rule %s missing Pattern", r.ID)
		}
		if r.Severity == "" {
			t.Errorf("rule %s missing Severity", r.ID)
		}
		validSev := r.Severity == "high" || r.Severity == "medium" || r.Severity == "low"
		if !validSev {
			t.Errorf("rule %s has invalid severity: %s", r.ID, r.Severity)
		}
	}
}

func TestBuiltinRulesContainKeyProviders(t *testing.T) {
	rules := BuiltinRules()
	ids := make(map[string]bool)
	for _, r := range rules {
		ids[r.ID] = true
	}
	expected := []string{"aws-access-key", "aws-secret-key", "github-token", "slack-token", "private-key", "generic-high-entropy"}
	for _, id := range expected {
		if !ids[id] {
			t.Errorf("missing expected builtin rule: %s", id)
		}
	}
}
