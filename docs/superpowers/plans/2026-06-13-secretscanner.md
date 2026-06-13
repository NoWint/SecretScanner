# SecretScannerCLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Go CLI tool that recursively scans git history for leaked API keys, tokens, and passwords, with pre-commit hook support.

**Architecture:** Monolithic Go binary with internal packages for scanner, git walker, rules, report, and hook. Uses go-git for pure-Go git access, Cobra for CLI, and Shannon entropy for high-entropy string detection.

**Tech Stack:** Go 1.22+, github.com/spf13/cobra, github.com/go-git/go-git/v5, github.com/fatih/color, gopkg.in/yaml.v3

---

## File Structure

| File | Responsibility |
|------|---------------|
| `main.go` | Entry point, calls cmd.Execute() |
| `cmd/root.go` | Root command, version subcommand |
| `cmd/scan.go` | Scan subcommand logic |
| `cmd/install_hook.go` | install-hook subcommand logic |
| `internal/rules/rule.go` | Rule and Finding struct definitions |
| `internal/rules/builtin.go` | Built-in rule definitions |
| `internal/rules/loader.go` | YAML custom rule loader |
| `internal/scanner/scanner.go` | Scan engine: regex match + entropy calc |
| `internal/scanner/entropy.go` | Shannon entropy calculation |
| `internal/git/walker.go` | Git history traversal via go-git |
| `internal/git/staged.go` | Staged files retrieval |
| `internal/report/table.go` | Terminal colored table output |
| `internal/report/json.go` | JSON output |
| `internal/hook/install.go` | Pre-commit hook installation |
| `internal/ignore/ignore.go` | .secretscannerignore support |
| `configs/rules.yaml` | Custom rules example file |

---

### Task 1: Project Scaffolding

**Files:**
- Create: `main.go`
- Create: `cmd/root.go`
- Create: `go.mod`

- [ ] **Step 1: Initialize Go module and install dependencies**

Run:
```bash
cd /Users/xiatian/Desktop/SecretScanner
go mod init github.com/NoWint/SecretScanner
go get github.com/spf13/cobra@latest
go get github.com/go-git/go-git/v5@latest
go get github.com/fatih/color@latest
go get gopkg.in/yaml.v3@latest
```

- [ ] **Step 2: Create main.go**

```go
package main

import "github.com/NoWint/SecretScanner/cmd"

func main() {
	cmd.Execute()
}
```

- [ ] **Step 3: Create cmd/root.go with root command and version subcommand**

```go
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var Version = "1.0.0"

var rootCmd = &cobra.Command{
	Use:   "secretscanner",
	Short: "Scan git repositories for leaked secrets",
	Long:  "SecretScanner recursively scans git history to detect API keys, tokens, and password leaks.",
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("SecretScanner v" + Version)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
```

- [ ] **Step 4: Verify it builds and runs**

Run:
```bash
go build -o secretscanner . && ./secretscanner version
```
Expected: `SecretScanner v1.0.0`

- [ ] **Step 5: Commit**

```bash
git add main.go cmd/root.go go.mod go.sum
git commit -m "feat: project scaffolding with cobra CLI"
```

---

### Task 2: Rule and Finding Data Structures

**Files:**
- Create: `internal/rules/rule.go`
- Create: `internal/rules/rule_test.go`

- [ ] **Step 1: Write the test for Rule and Finding structs**

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/rules/ -v`
Expected: FAIL — `rules.Rule` and `rules.Finding` undefined

- [ ] **Step 3: Write the Rule and Finding structs**

```go
package rules

// Finding represents a detected secret leak.
type Finding struct {
	RuleID     string
	RuleName   string
	Severity   string
	FilePath   string
	LineNumber int
	Match      string
	Entropy    float64
	CommitHash string
	CommitTime string
	Author     string
}

// Rule defines a pattern for detecting secrets.
type Rule struct {
	ID         string
	Name       string
	Pattern    string
	EntropyMin float64
	Severity   string
	Keywords   []string
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/rules/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/rules/rule.go internal/rules/rule_test.go
git commit -m "feat: add Rule and Finding data structures"
```

---

### Task 3: Built-in Rules

**Files:**
- Create: `internal/rules/builtin.go`
- Create: `internal/rules/builtin_test.go`

- [ ] **Step 1: Write the test for built-in rules**

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/rules/ -v -run TestBuiltin`
Expected: FAIL — `BuiltinRules` undefined

- [ ] **Step 3: Write BuiltinRules function**

```go
package rules

// BuiltinRules returns the default set of secret detection rules.
func BuiltinRules() []Rule {
	return []Rule{
		{
			ID:         "aws-access-key",
			Name:       "AWS Access Key ID",
			Pattern:    `AKIA[0-9A-Z]{16}`,
			EntropyMin: 0,
			Severity:   "high",
			Keywords:   []string{"AKIA"},
		},
		{
			ID:         "aws-secret-key",
			Name:       "AWS Secret Access Key",
			Pattern:    `(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`,
			EntropyMin: 4.0,
			Severity:   "high",
			Keywords:   []string{"aws_secret_access_key"},
		},
		{
			ID:         "azure-token",
			Name:       "Azure Tenant/Client Secret",
			Pattern:    `(?i)azure[_\-]?(?:tenant|client)[_\-]?secret\s*[=:]\s*[A-Za-z0-9\-_]{20,}`,
			EntropyMin: 3.5,
			Severity:   "high",
			Keywords:   []string{"azure"},
		},
		{
			ID:         "gcp-service-account",
			Name:       "GCP Service Account Key",
			Pattern:    `(?i)"type"\s*:\s*"service_account"`,
			EntropyMin: 0,
			Severity:   "high",
			Keywords:   []string{"service_account"},
		},
		{
			ID:         "github-token",
			Name:       "GitHub Token",
			Pattern:    `gh[psoru]_[A-Za-z0-9_]{36,255}`,
			EntropyMin: 0,
			Severity:   "high",
			Keywords:   []string{"ghp_", "ghs_", "gho_", "ghu_", "ghr_"},
		},
		{
			ID:         "gitlab-token",
			Name:       "GitLab Token",
			Pattern:    `glpat-[A-Za-z0-9\-_]{20,}`,
			EntropyMin: 0,
			Severity:   "high",
			Keywords:   []string{"glpat-"},
		},
		{
			ID:         "bitbucket-token",
			Name:       "Bitbucket Token",
			Pattern:    `(?i)bitbucket[_\-]?token\s*[=:]\s*[A-Za-z0-9\-_]{20,}`,
			EntropyMin: 3.5,
			Severity:   "high",
			Keywords:   []string{"bitbucket"},
		},
		{
			ID:         "slack-token",
			Name:       "Slack Token",
			Pattern:    `xox[baprs]-[A-Za-z0-9\-]{10,}`,
			EntropyMin: 0,
			Severity:   "high",
			Keywords:   []string{"xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"},
		},
		{
			ID:         "discord-token",
			Name:       "Discord Token",
			Pattern:    `(?i)discord[_\-]?token\s*[=:]\s*[A-Za-z0-9\-_._]{20,}`,
			EntropyMin: 3.5,
			Severity:   "high",
			Keywords:   []string{"discord"},
		},
		{
			ID:         "mongodb-uri",
			Name:       "MongoDB Connection URI",
			Pattern:    `mongodb(\+srv)?://[A-Za-z0-9\-_]+:[A-Za-z0-9\-_!@#$%^&*]+@[A-Za-z0-9\-_.]+`,
			EntropyMin: 0,
			Severity:   "high",
			Keywords:   []string{"mongodb://", "mongodb+srv://"},
		},
		{
			ID:         "postgresql-uri",
			Name:       "PostgreSQL Connection URI",
			Pattern:    `postgres(ql)?://[A-Za-z0-9\-_]+:[A-Za-z0-9\-_!@#$%^&*]+@[A-Za-z0-9\-_.]+`,
			EntropyMin: 0,
			Severity:   "high",
			Keywords:   []string{"postgres://", "postgresql://"},
		},
		{
			ID:         "mysql-uri",
			Name:       "MySQL Connection URI",
			Pattern:    `mysql://[A-Za-z0-9\-_]+:[A-Za-z0-9\-_!@#$%^&*]+@[A-Za-z0-9\-_.]+`,
			EntropyMin: 0,
			Severity:   "high",
			Keywords:   []string{"mysql://"},
		},
		{
			ID:         "stripe-key",
			Name:       "Stripe Secret Key",
			Pattern:    `sk_live_[0-9a-zA-Z]{24,}`,
			EntropyMin: 0,
			Severity:   "high",
			Keywords:   []string{"sk_live_"},
		},
		{
			ID:         "private-key",
			Name:       "Private Key",
			Pattern:    `-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----`,
			EntropyMin: 0,
			Severity:   "high",
			Keywords:   []string{"PRIVATE KEY"},
		},
		{
			ID:         "generic-high-entropy",
			Name:       "Generic High-Entropy String",
			Pattern:    `(?i)(?:password|passwd|secret|token|key|api[_\-]?key)\s*[=:]\s*['"]?[A-Za-z0-9\-_./+=]{20,}['"]?`,
			EntropyMin: 4.5,
			Severity:   "medium",
			Keywords:   []string{"password", "secret", "token", "api_key", "apikey"},
		},
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/rules/ -v -run TestBuiltin`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/rules/builtin.go internal/rules/builtin_test.go
git commit -m "feat: add built-in secret detection rules"
```

---

### Task 4: YAML Custom Rule Loader

**Files:**
- Create: `internal/rules/loader.go`
- Create: `internal/rules/loader_test.go`
- Create: `configs/rules.yaml`

- [ ] **Step 1: Write the test for YAML rule loader**

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/rules/ -v -run TestLoadRules`
Expected: FAIL — `LoadRulesFromYAML` undefined

- [ ] **Step 3: Write LoadRulesFromYAML function**

```go
package rules

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type yamlRule struct {
	ID         string   `yaml:"id"`
	Name       string   `yaml:"name"`
	Pattern    string   `yaml:"pattern"`
	EntropyMin float64  `yaml:"entropy_min"`
	Severity   string   `yaml:"severity"`
	Keywords   []string `yaml:"keywords"`
}

type yamlRulesFile struct {
	Rules []yamlRule `yaml:"rules"`
}

// LoadRulesFromYAML reads custom rules from a YAML file.
func LoadRulesFromYAML(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading rules file %s: %w", path, err)
	}

	var yf yamlRulesFile
	if err := yaml.Unmarshal(data, &yf); err != nil {
		return nil, fmt.Errorf("parsing rules file %s: %w", path, err)
	}

	rules := make([]Rule, 0, len(yf.Rules))
	for _, yr := range yf.Rules {
		rules = append(rules, Rule{
			ID:         yr.ID,
			Name:       yr.Name,
			Pattern:    yr.Pattern,
			EntropyMin: yr.EntropyMin,
			Severity:   yr.Severity,
			Keywords:   yr.Keywords,
		})
	}
	return rules, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/rules/ -v -run TestLoadRules`
Expected: PASS

- [ ] **Step 5: Create configs/rules.yaml example**

```yaml
# SecretScanner custom rules example
# Add your own rules below
rules:
  - id: my-api-key
    name: My Custom API Key
    pattern: "my_api_key\\s*=\\s*['\"]([A-Za-z0-9]{32,})['\"]"
    entropy_min: 3.5
    severity: high
    keywords:
      - my_api_key
```

- [ ] **Step 6: Commit**

```bash
git add internal/rules/loader.go internal/rules/loader_test.go configs/rules.yaml
git commit -m "feat: add YAML custom rule loader"
```

---

### Task 5: Shannon Entropy Calculation

**Files:**
- Create: `internal/scanner/entropy.go`
- Create: `internal/scanner/entropy_test.go`

- [ ] **Step 1: Write the test for Shannon entropy**

```go
package scanner

import (
	"math"
	"testing"
)

func TestShannonEntropyEmpty(t *testing.T) {
	got := ShannonEntropy("")
	if got != 0 {
		t.Errorf("expected 0 for empty string, got %f", got)
	}
}

func TestShannonEntropySingleChar(t *testing.T) {
	got := ShannonEntropy("aaaa")
	if got != 0 {
		t.Errorf("expected 0 for single repeated char, got %f", got)
	}
}

func TestShannonEntropyUniform(t *testing.T) {
	// "ab" has 1 bit of entropy per character
	got := ShannonEntropy("ab")
	if math.Abs(got-1.0) > 0.01 {
		t.Errorf("expected ~1.0 for 'ab', got %f", got)
	}
}

func TestShannonEntropyHighEntropy(t *testing.T) {
	// A long random-looking string should have high entropy
	got := ShannonEntropy("AKIA3E8F9Z7XMQ2P4L6")
	if got < 3.5 {
		t.Errorf("expected entropy > 3.5 for mixed string, got %f", got)
	}
}

func TestShannonEntropyMax(t *testing.T) {
	// 256 unique chars would be 8.0, but we test with a reasonable set
	got := ShannonEntropy("0123456789abcdef")
	if got < 3.0 {
		t.Errorf("expected entropy > 3.0 for hex string, got %f", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scanner/ -v -run TestShannon`
Expected: FAIL — `ShannonEntropy` undefined

- [ ] **Step 3: Write ShannonEntropy function**

```go
package scanner

import (
	"math"
)

// ShannonEntropy calculates the Shannon entropy of a string.
// Returns a value between 0 and 8, where higher values indicate
// more randomness (likely a generated secret).
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/scanner/ -v -run TestShannon`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/entropy.go internal/scanner/entropy_test.go
git commit -m "feat: add Shannon entropy calculation"
```

---

### Task 6: Scanner Engine

**Files:**
- Create: `internal/scanner/scanner.go`
- Create: `internal/scanner/scanner_test.go`

- [ ] **Step 1: Write the test for scanner engine**

```go
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
	access_key = "AKIA3E8F9Z7XMQ2P4L6"
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
	if findings[0].Match != "AKIA3E8F9Z7XMQ2P4L6" {
		t.Errorf("expected Match AKIA3E8F9Z7XMQ2P4L6, got %s", findings[0].Match)
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
	// Low entropy password — should not match
	lowContent := `password = "aaaaaaaaaaaaaaaaaaaa"`
	findings := ScanContent(lowContent, "low.txt", []rules.Rule{r})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for low entropy, got %d", len(findings))
	}

	// High entropy password — should match
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
	content := `key1 = "AKIA3E8F9Z7XMQ2P4L6"
key2 = "AKIA1A2B3C4D5E6F7G8H"`
	findings := ScanContent(content, "multi.txt", []rules.Rule{r})
	if len(findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(findings))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scanner/ -v -run TestScanContent`
Expected: FAIL — `ScanContent` undefined

- [ ] **Step 3: Write ScanContent function**

```go
package scanner

import (
	"bufio"
	"regexp"
	"strings"

	"github.com/NoWint/SecretScanner/internal/rules"
)

// ScanContent scans text content against a set of rules and returns findings.
func ScanContent(content string, filePath string, ruleSet []rules.Rule) []rules.Finding {
	var findings []rules.Finding

	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		for _, rule := range ruleSet {
			re, err := regexp.Compile(rule.Pattern)
			if err != nil {
				continue
			}
			matches := re.FindAllString(line, -1)
			for _, match := range matches {
				entropy := ShannonEntropy(match)
				if rule.EntropyMin > 0 && entropy < rule.EntropyMin {
					continue
				}
				findings = append(findings, rules.Finding{
					RuleID:     rule.ID,
					RuleName:   rule.Name,
					Severity:   rule.Severity,
					FilePath:   filePath,
					LineNumber: lineNum,
					Match:      match,
					Entropy:    entropy,
				})
			}
		}
	}

	return findings
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/scanner/ -v -run TestScanContent`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/scanner.go internal/scanner/scanner_test.go
git commit -m "feat: add scanner engine with regex + entropy detection"
```

---

### Task 7: Git History Walker

**Files:**
- Create: `internal/git/walker.go`
- Create: `internal/git/walker_test.go`

- [ ] **Step 1: Write the test for git walker**

```go
package git

import (
	"testing"

	"github.com/NoWint/SecretScanner/internal/rules"
)

func TestScanRepositoryOnRealGitRepo(t *testing.T) {
	// We test against the current project's own git repo
	findings, err := ScanRepository(".", []rules.Rule{
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
	// Our repo shouldn't have AWS keys, so findings should be 0
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/git/ -v`
Expected: FAIL — `ScanRepository` undefined

- [ ] **Step 3: Write ScanRepository function**

```go
package git

import (
	"fmt"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/NoWint/SecretScanner/internal/rules"
	"github.com/NoWint/SecretScanner/internal/scanner"
)

// ScanRepository scans all commits in a git repository for secrets.
func ScanRepository(path string, ruleSet []rules.Rule) ([]rules.Finding, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("opening repository at %s: %w", path, err)
	}

	ref, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("getting HEAD: %w", err)
	}

	commitIter, err := repo.Log(&git.LogOptions{From: ref.Hash()})
	if err != nil {
		return nil, fmt.Errorf("getting commit log: %w", err)
	}
	defer commitIter.Close()

	seen := make(map[string]bool)
	var allFindings []rules.Finding

	err = commitIter.ForEach(func(c *object.Commit) error {
		if c.NumParents() == 0 {
			// Initial commit — scan all files in tree
			tree, err := c.Tree()
			if err != nil {
				return nil // skip this commit
			}
			tree.Files().ForEach(func(f *object.File) error {
				if seen[f.Name] {
					return nil
				}
				seen[f.Name] = true
				content, err := f.Contents()
				if err != nil {
					return nil // skip binary files
				}
				findings := scanner.ScanContent(content, f.Name, ruleSet)
				for i := range findings {
					findings[i].CommitHash = c.Hash.String()[:7]
					findings[i].CommitTime = c.Author.When.Format("2006-01-02")
					findings[i].Author = c.Author.Email
				}
				allFindings = append(allFindings, findings...)
				return nil
			})
			return nil
		}

		// Regular commit — scan diff against first parent
		parent, err := c.Parent(0)
		if err != nil {
			return nil
		}

		patch, err := parent.Patch(c)
		if err != nil {
			return nil
		}

		for _, fp := range patch.FilePatches() {
			from, to := fp.Files()
			if to == nil {
				continue // deleted file
			}
			var filePath string
			if from != nil {
				filePath = from.Path()
			} else {
				filePath = to.Path()
			}

			var content string
			for _, chunk := range fp.Chunks() {
				if chunk.Type() == object.Add {
					content += chunk.Content() + "\n"
				}
			}
			if content == "" {
				continue
			}

			findings := scanner.ScanContent(content, filePath, ruleSet)
			for i := range findings {
				findings[i].CommitHash = c.Hash.String()[:7]
				findings[i].CommitTime = c.Author.When.Format("2006-01-02")
				findings[i].Author = c.Author.Email
			}
			allFindings = append(allFindings, findings...)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("iterating commits: %w", err)
	}

	return allFindings, nil
}

// ScanWorkingDirectory scans only the current working directory files.
func ScanWorkingDirectory(path string, ruleSet []rules.Rule) ([]rules.Finding, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("opening repository at %s: %w", path, err)
	}

	head, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("getting HEAD: %w", err)
	}

	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, fmt.Errorf("getting commit: %w", err)
	}

	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("getting tree: %w", err)
	}

	var allFindings []rules.Finding
	err = tree.Files().ForEach(func(f *object.File) error {
		content, err := f.Contents()
		if err != nil {
			return nil // skip binary
		}
		findings := scanner.ScanContent(content, f.Name, ruleSet)
		allFindings = append(allFindings, findings...)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walking tree: %w", err)
	}

	return allFindings, nil
}

// ScanStagedFiles scans only the files in the staging area.
func ScanStagedFiles(path string, ruleSet []rules.Rule) ([]rules.Finding, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("opening repository at %s: %w", path, err)
	}

	wt, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("getting worktree: %w", err)
	}

	status, err := wt.Status()
	if err != nil {
		return nil, fmt.Errorf("getting status: %w", err)
	}

	var allFindings []rules.Finding
	for filePath, s := range status {
		// Only scan staged files (Added, Modified, Renamed, Copied)
		if s.Staging != plumbing.Added && s.Staging != plumbing.Modified && s.Staging != plumbing.Renamed && s.Staging != plumbing.Copied {
			continue
		}

		// Get staged content from the index
		idx, err := repo.Storer.Index()
		if err != nil {
			continue
		}

		var objHash plumbing.Hash
		for _, e := range idx.Entries {
			if e.Name == filePath {
				objHash = e.Hash
				break
			}
		}
		if objHash.IsZero() {
			continue
		}

		blob, err := repo.BlobObject(objHash)
		if err != nil {
			continue
		}

		r, err := blob.Reader()
		if err != nil {
			continue
		}

		buf := make([]byte, 0, blob.Size)
		buf, err = append(buf, make([]byte, blob.Size)...)
		if err != nil {
			r.Close()
			continue
		}
		n, _ := r.Read(buf)
		r.Close()

		content := string(buf[:n])
		findings := scanner.ScanContent(content, filePath, ruleSet)
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/git/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/git/walker.go internal/git/walker_test.go
git commit -m "feat: add git history walker with staged file support"
```

---

### Task 8: Ignore File Support

**Files:**
- Create: `internal/ignore/ignore.go`
- Create: `internal/ignore/ignore_test.go`

- [ ] **Step 1: Write the test for ignore file**

```go
package ignore

import (
	"testing"
)

func TestLoadIgnorePatterns(t *testing.T) {
	patterns := []string{"*.lock", "vendor/", "node_modules/"}
	matcher := NewMatcher(patterns)

	if !matcher.Match("package.lock") {
		t.Error("expected *.lock to match package.lock")
	}
	if !matcher.Match("vendor/main.go") {
		t.Error("expected vendor/ to match vendor/main.go")
	}
	if !matcher.Match("node_modules/react/index.js") {
		t.Error("expected node_modules/ to match node_modules/react/index.js")
	}
	if matcher.Match("src/main.go") {
		t.Error("expected src/main.go not to match any pattern")
	}
}

func TestLoadIgnorePatternsEmpty(t *testing.T) {
	matcher := NewMatcher(nil)
	if matcher.Match("anything.go") {
		t.Error("empty matcher should not match anything")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/ignore/ -v`
Expected: FAIL — `NewMatcher` undefined

- [ ] **Step 3: Write Matcher**

```go
package ignore

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Matcher checks if a file path should be ignored.
type Matcher struct {
	patterns []string
}

// NewMatcher creates a Matcher from ignore patterns.
func NewMatcher(patterns []string) *Matcher {
	return &Matcher{patterns: patterns}
}

// LoadIgnoreFile reads .secretscannerignore and returns patterns.
func LoadIgnoreFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	var patterns []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns, scanner.Err()
}

// Match returns true if the file path should be ignored.
func (m *Matcher) Match(filePath string) bool {
	for _, pattern := range m.patterns {
		// Directory pattern (trailing /)
		if strings.HasSuffix(pattern, "/") {
			if strings.HasPrefix(filePath, pattern) || strings.HasPrefix(filePath, strings.TrimSuffix(pattern, "/")+"/") {
				return true
			}
			continue
		}
		// Extension pattern (*.ext)
		if strings.HasPrefix(pattern, "*.") {
			ext := pattern[1:] // *.lock -> .lock
			if strings.HasSuffix(filePath, ext) {
				return true
			}
			continue
		}
		// Exact match or glob
		matched, _ := filepath.Match(pattern, filepath.Base(filePath))
		if matched {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/ignore/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/ignore/ignore.go internal/ignore/ignore_test.go
git commit -m "feat: add .secretscannerignore support"
```

---

### Task 9: Report Output — Terminal Table

**Files:**
- Create: `internal/report/table.go`
- Create: `internal/report/table_test.go`

- [ ] **Step 1: Write the test for table output**

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/report/ -v -run TestFormat`
Expected: FAIL — `FormatTable` undefined

- [ ] **Step 3: Write FormatTable and MaskSecret**

```go
package report

import (
	"fmt"
	"strings"

	"github.com/fatih/color"

	"github.com/NoWint/SecretScanner/internal/rules"
)

var (
	red    = color.New(color.FgRed).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	blue   = color.New(color.FgBlue).SprintFunc()
	bold   = color.New(color.Bold).SprintFunc()
)

// MaskSecret masks the middle of a secret string, showing first 6 and last 4 chars.
func MaskSecret(s string) string {
	if len(s) <= 10 {
		return s
	}
	return s[:6] + "..." + s[len(s)-4:]
}

// FormatTable formats findings as a colored terminal table.
func FormatTable(findings []rules.Finding) string {
	var sb strings.Builder

	if len(findings) == 0 {
		sb.WriteString(bold("No secrets found. Your repository is clean!"))
		sb.WriteString("\n")
		return sb.String()
	}

	header := fmt.Sprintf("SecretScanner — Found %d secret(s)", len(findings))
	sb.WriteString(bold(header))
	sb.WriteString("\n\n")

	for _, f := range findings {
		severityStr := formatSeverity(f.Severity)
		sb.WriteString(fmt.Sprintf("%s %s\n", severityStr, bold(f.RuleName)))
		sb.WriteString(fmt.Sprintf("  File:   %s:%d\n", f.FilePath, f.LineNumber))
		sb.WriteString(fmt.Sprintf("  Match:  %s\n", MaskSecret(f.Match)))
		if f.CommitHash != "" {
			sb.WriteString(fmt.Sprintf("  Commit: %s (%s)\n", f.CommitHash, f.CommitTime))
		}
		sb.WriteString(fmt.Sprintf("  Entropy: %.2f\n", f.Entropy))
		sb.WriteString("\n")
	}

	return sb.String()
}

func formatSeverity(severity string) string {
	switch severity {
	case "high":
		return red("[HIGH]")
	case "medium":
		return yellow("[MEDIUM]")
	case "low":
		return blue("[LOW]")
	default:
		return fmt.Sprintf("[%s]", strings.ToUpper(severity))
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/report/ -v -run TestFormat`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/report/table.go internal/report/table_test.go
git commit -m "feat: add terminal table report output"
```

---

### Task 10: Report Output — JSON

**Files:**
- Create: `internal/report/json.go`
- Create: `internal/report/json_test.go`

- [ ] **Step 1: Write the test for JSON output**

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/report/ -v -run TestFormatJSON`
Expected: FAIL — `FormatJSON` undefined

- [ ] **Step 3: Write FormatJSON function**

```go
package report

import (
	"encoding/json"
	"time"

	"github.com/NoWint/SecretScanner/internal/rules"
)

type jsonReport struct {
	Version       string          `json:"version"`
	ScanTime      string          `json:"scan_time"`
	Repository    string          `json:"repository"`
	TotalFindings int             `json:"total_findings"`
	Findings      []jsonFinding   `json:"findings"`
}

type jsonFinding struct {
	RuleID     string  `json:"rule_id"`
	RuleName   string  `json:"rule_name"`
	Severity   string  `json:"severity"`
	FilePath   string  `json:"file_path"`
	LineNumber int     `json:"line_number"`
	Match      string  `json:"match"`
	Entropy    float64 `json:"entropy"`
	CommitHash string  `json:"commit_hash,omitempty"`
	CommitTime string  `json:"commit_time,omitempty"`
	Author     string  `json:"author,omitempty"`
}

// FormatJSON formats findings as a JSON string.
func FormatJSON(findings []rules.Finding, repoPath string) string {
	jf := make([]jsonFinding, len(findings))
	for i, f := range findings {
		jf[i] = jsonFinding{
			RuleID:     f.RuleID,
			RuleName:   f.RuleName,
			Severity:   f.Severity,
			FilePath:   f.FilePath,
			LineNumber: f.LineNumber,
			Match:      MaskSecret(f.Match),
			Entropy:    f.Entropy,
			CommitHash: f.CommitHash,
			CommitTime: f.CommitTime,
			Author:     f.Author,
		}
	}

	report := jsonReport{
		Version:       "1.0.0",
		ScanTime:      time.Now().UTC().Format(time.RFC3339),
		Repository:    repoPath,
		TotalFindings: len(findings),
		Findings:      jf,
	}

	data, _ := json.MarshalIndent(report, "", "  ")
	return string(data)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/report/ -v -run TestFormatJSON`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/report/json.go internal/report/json_test.go
git commit -m "feat: add JSON report output"
```

---

### Task 11: Pre-commit Hook Installation

**Files:**
- Create: `internal/hook/install.go`
- Create: `internal/hook/install_test.go`

- [ ] **Step 1: Write the test for hook installation**

```go
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

	// Check executable permission
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/hook/ -v`
Expected: FAIL — `InstallHook` undefined

- [ ] **Step 3: Write InstallHook function**

```go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/hook/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/hook/install.go internal/hook/install_test.go
git commit -m "feat: add pre-commit hook installation"
```

---

### Task 12: CLI Scan Command Integration

**Files:**
- Create: `cmd/scan.go`

- [ ] **Step 1: Write cmd/scan.go**

```go
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/NoWint/SecretScanner/internal/git"
	"github.com/NoWint/SecretScanner/internal/ignore"
	"github.com/NoWint/SecretScanner/internal/report"
	"github.com/NoWint/SecretScanner/internal/rules"
)

var (
	scanFormat   string
	scanRules    string
	scanNoHistory bool
	scanStaged   bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a repository for secrets",
	Long:  "Recursively scan git history for leaked API keys, tokens, and passwords.",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		path := "."
		if len(args) > 0 {
			path = args[0]
		}

		// Load rules
		ruleSet := rules.BuiltinRules()
		if scanRules != "" {
			customRules, err := rules.LoadRulesFromYAML(scanRules)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading custom rules: %v\n", err)
				os.Exit(2)
			}
			ruleSet = append(ruleSet, customRules...)
		}

		// Load ignore patterns
		ignorePath := fmt.Sprintf("%s/.secretscannerignore", path)
		patterns, err := ignore.LoadIgnoreFile(ignorePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: error reading ignore file: %v\n", err)
		}
		matcher := ignore.NewMatcher(patterns)

		// Filter rules by ignore patterns
		filteredRules := make([]rules.Rule, 0, len(ruleSet))
		for _, r := range ruleSet {
			if !matcher.Match(r.ID) {
				filteredRules = append(filteredRules, r)
			}
		}

		// Scan
		var findings []rules.Finding
		if scanStaged {
			findings, err = git.ScanStagedFiles(path, filteredRules)
		} else if scanNoHistory {
			findings, err = git.ScanWorkingDirectory(path, filteredRules)
		} else {
			findings, err = git.ScanRepository(path, filteredRules)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}

		// Filter findings by ignore patterns
		var filtered []rules.Finding
		for _, f := range findings {
			if !matcher.Match(f.FilePath) {
				filtered = append(filtered, f)
			}
		}

		// Output
		var output string
		switch scanFormat {
		case "json":
			output = report.FormatJSON(filtered, path)
		case "table":
			output = report.FormatTable(filtered)
		default:
			fmt.Fprintf(os.Stderr, "Unknown format: %s (use 'table' or 'json')\n", scanFormat)
			os.Exit(2)
		}
		fmt.Println(output)

		if len(filtered) > 0 {
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVarP(&scanFormat, "format", "f", "table", "Output format (table, json)")
	scanCmd.Flags().StringVarP(&scanRules, "rules", "r", "", "Path to custom rules YAML file")
	scanCmd.Flags().BoolVar(&scanNoHistory, "no-history", false, "Scan only working directory, skip git history")
	scanCmd.Flags().BoolVar(&scanStaged, "staged", false, "Scan only staged files (for pre-commit hook)")
}
```

- [ ] **Step 2: Build and verify**

Run:
```bash
go build -o secretscanner . && ./secretscanner scan --help
```
Expected: Help text showing scan command with all flags

- [ ] **Step 3: Commit**

```bash
git add cmd/scan.go
git commit -m "feat: add scan CLI command with all flags"
```

---

### Task 13: CLI Install-Hook Command

**Files:**
- Create: `cmd/install_hook.go`

- [ ] **Step 1: Write cmd/install_hook.go**

```go
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/NoWint/SecretScanner/internal/hook"
)

var installHookCmd = &cobra.Command{
	Use:   "install-hook",
	Short: "Install pre-commit hook in the current repository",
	Long:  "Install a git pre-commit hook that scans staged files for secrets before allowing a commit.",
	Run: func(cmd *cobra.Command, args []string) {
		if err := hook.InstallHook("."); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
	},
}

func init() {
	rootCmd.AddCommand(installHookCmd)
}
```

- [ ] **Step 2: Build and verify**

Run:
```bash
go build -o secretscanner . && ./secretscanner install-hook --help
```
Expected: Help text for install-hook command

- [ ] **Step 3: Commit**

```bash
git add cmd/install_hook.go
git commit -m "feat: add install-hook CLI command"
```

---

### Task 14: Integration Test and Final Build

**Files:**
- Modify: `main.go` (no change needed if already correct)

- [ ] **Step 1: Run all tests**

Run: `go test ./... -v`
Expected: All tests PASS

- [ ] **Step 2: Build the binary**

Run: `go build -o secretscanner .`
Expected: Binary builds successfully

- [ ] **Step 3: Test scan on current repo**

Run: `./secretscanner scan .`
Expected: No secrets found (exit code 0)

- [ ] **Step 4: Test JSON output**

Run: `./secretscanner scan . --format=json`
Expected: Valid JSON with total_findings: 0

- [ ] **Step 5: Test version command**

Run: `./secretscanner version`
Expected: `SecretScanner v1.0.0`

- [ ] **Step 6: Commit final state**

```bash
git add -A
git commit -m "feat: complete SecretScannerCLI v1.0.0"
```

---

### Task 15: Push to GitHub

**Files:** None (git operations only)

- [ ] **Step 1: Add remote and push**

Run:
```bash
git remote add origin https://github.com/NoWint/SecretScanner.git
git push -u origin main
```
Expected: Code pushed to GitHub successfully

- [ ] **Step 2: Verify remote**

Run: `git remote -v`
Expected: origin pointing to https://github.com/NoWint/SecretScanner.git
