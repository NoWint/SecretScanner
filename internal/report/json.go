package report

import (
	"encoding/json"
	"time"

	"github.com/NoWint/SecretScanner/internal/rules"
)

type jsonReport struct {
	Version       string        `json:"version"`
	ScanTime      string        `json:"scan_time"`
	Repository    string        `json:"repository"`
	TotalFindings int           `json:"total_findings"`
	Findings      []jsonFinding `json:"findings"`
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
