package scanner

import (
	"testing"

	"github.com/NoWint/SecretScanner/internal/rules"
)

func TestScanContentFindsAWSKey(t *testing.T) {
	r := rules.Rule{
		ID:         "aws-access-key",
		Name:       "AWS Access Key ID",
		Pattern:    `AKIA[0-9A-Z]{16}`,
		EntropyMin: 0,
		Severity:   "high",
		Keywords:   []string{"AKIA"},
	}
	content := `config = {
	access_key = "AKIA3E8F9Z7XMQ2P4L6N"
}`
	findings := ScanContent(content, "config.txt", []rules.Rule{r})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "aws-access-key" {
		t.Errorf("expected RuleID aws-access-key, got %s", findings[0].RuleID)
	}
	if findings[0].FilePath != "config.txt" {
		t.Errorf("expected FilePath config.txt, got %s", findings[0].FilePath)
	}
	if findings[0].Match != "AKIA3E8F9Z7XMQ2P4L6N" {
		t.Errorf("expected Match AKIA3E8F9Z7XMQ2P4L6N, got %s", findings[0].Match)
	}
	if findings[0].LineNumber != 2 {
		t.Errorf("expected LineNumber 2, got %d", findings[0].LineNumber)
	}
}

func TestScanContentWithEntropyFilter(t *testing.T) {
	r := rules.Rule{
		ID:         "generic-high-entropy",
		Name:       "Generic High-Entropy String",
		Pattern:    `(?i)password\s*[=:]\s*['"]?([A-Za-z0-9]{20,})['"]?`,
		EntropyMin: 4.5,
		Severity:   "medium",
		Keywords:   []string{"password"},
	}
	lowContent := `password = "aaaaaaaaaaaaaaaaaaaa"`
	findings := ScanContent(lowContent, "low.txt", []rules.Rule{r})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for low entropy, got %d", len(findings))
	}

	highContent := `password = "xK9mP2qR7vL3nB5wY8jF4"`
	findings = ScanContent(highContent, "high.txt", []rules.Rule{r})
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for high entropy, got %d", len(findings))
	}
}

func TestScanContentNoMatch(t *testing.T) {
	r := rules.Rule{
		ID:         "aws-access-key",
		Name:       "AWS Access Key ID",
		Pattern:    `AKIA[0-9A-Z]{16}`,
		EntropyMin: 0,
		Severity:   "high",
		Keywords:   []string{"AKIA"},
	}
	content := "no secrets here"
	findings := ScanContent(content, "clean.txt", []rules.Rule{r})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanContentMultipleMatches(t *testing.T) {
	r := rules.Rule{
		ID:         "aws-access-key",
		Name:       "AWS Access Key ID",
		Pattern:    `AKIA[0-9A-Z]{16}`,
		EntropyMin: 0,
		Severity:   "high",
		Keywords:   []string{"AKIA"},
	}
	content := `key1 = "AKIA3E8F9Z7XMQ2P4L6N"
key2 = "AKIA1A2B3C4D5E6F7G8H"`
	findings := ScanContent(content, "multi.txt", []rules.Rule{r})
	if len(findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(findings))
	}
}
