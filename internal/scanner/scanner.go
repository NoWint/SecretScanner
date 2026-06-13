package scanner

import (
	"bufio"
	"regexp"
	"strings"

	"github.com/NoWint/SecretScanner/internal/rules"
)

// compiledRule is a rule with its regex pre-compiled for performance.
type compiledRule struct {
	Rule *rules.Rule
	RE   *regexp.Regexp
}

// ScanContent scans text content against a set of rules and returns findings.
func ScanContent(content string, filePath string, ruleSet []rules.Rule) []rules.Finding {
	var findings []rules.Finding

	// Pre-compile regexes once per rule, not per line
	compiled := make([]compiledRule, 0, len(ruleSet))
	for i := range ruleSet {
		re, err := regexp.Compile(ruleSet[i].Pattern)
		if err != nil {
			continue
		}
		compiled = append(compiled, compiledRule{Rule: &ruleSet[i], RE: re})
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	// Increase buffer size to handle long lines (minified JS, base64, etc.)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		for _, cr := range compiled {
			matches := cr.RE.FindAllString(line, -1)
			for _, match := range matches {
				entropy := ShannonEntropy(match)
				if cr.Rule.EntropyMin > 0 && entropy < cr.Rule.EntropyMin {
					continue
				}
				findings = append(findings, rules.Finding{
					RuleID:     cr.Rule.ID,
					RuleName:   cr.Rule.Name,
					Severity:   cr.Rule.Severity,
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
