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
