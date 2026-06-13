package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRulesFromYAML(t *testing.T) {
	content := `
rules:
  - id: my-api-key
    name: My Custom API Key
    pattern: "my_api_key\\s*=\\s*['\"]([A-Za-z0-9]{32,})['\"]"
    entropy_min: 3.5
    severity: high
    keywords:
      - my_api_key
`
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadRulesFromYAML(path)
	if err != nil {
		t.Fatalf("LoadRulesFromYAML returned error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if r.ID != "my-api-key" {
		t.Errorf("expected ID my-api-key, got %s", r.ID)
	}
	if r.EntropyMin != 3.5 {
		t.Errorf("expected EntropyMin 3.5, got %f", r.EntropyMin)
	}
	if r.Severity != "high" {
		t.Errorf("expected severity high, got %s", r.Severity)
	}
}

func TestLoadRulesFromYAMLInvalidPath(t *testing.T) {
	_, err := LoadRulesFromYAML("/nonexistent/rules.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadRulesFromYAMLInvalidContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("not: valid: yaml: ["), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadRulesFromYAML(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}
