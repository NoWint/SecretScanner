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
		sb.WriteString(bold("No secrets found. 0 secrets detected."))
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
			sb.WriteString(fmt.Sprintf("  Commit: %s (%s)\n", f.CommitHash, f.Date))
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
