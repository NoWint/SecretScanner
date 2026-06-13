package scanner

import (
	"bufio"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/NoWint/SecretScanner/internal/rules"
)

// binaryThreshold is the ratio of non-printable characters above which content
// is considered binary. Based on Git's heuristic (0.30).
const binaryThreshold = 0.30

// IsBinary checks if content appears to be binary data.
// Uses the same heuristic as Git: if more than 30% of the first 8KB
// contains non-printable characters (excluding common text chars), it's binary.
func IsBinary(content string) bool {
	sample := content
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	if len(sample) == 0 {
		return false
	}

	nonPrintable := 0
	for _, b := range []byte(sample) {
		if b < 0x20 && b != 0x09 && b != 0x0A && b != 0x0D {
			nonPrintable++
		}
	}

	// Also check if it's valid UTF-8
	if !utf8.ValidString(sample) {
		return true
	}

	return float64(nonPrintable)/float64(len(sample)) > binaryThreshold
}

// compiledRule is a rule with its regex pre-compiled for performance.
type compiledRule struct {
	Rule *rules.Rule
	RE   *regexp.Regexp
}

// ScanContent scans text content against a set of rules and returns findings.
// Returns nil if content appears to be binary.
func ScanContent(content string, filePath string, ruleSet []rules.Rule) []rules.Finding {
	if IsBinary(content) {
		return nil
	}

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
