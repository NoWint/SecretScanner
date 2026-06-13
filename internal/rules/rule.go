package rules

// Rule represents a secret detection rule.
type Rule struct {
	ID         string   // Unique identifier for the rule
	Name       string   // Human-readable name
	Pattern    string   // Regex pattern to match
	EntropyMin float64  // Minimum Shannon entropy threshold (0 = disabled)
	Severity   string   // "high", "medium", or "low"
	Keywords   []string // Keywords for pre-filtering
}

// Finding represents a discovered secret.
type Finding struct {
	RuleID     string  // ID of the matched rule
	RuleName   string  // Name of the matched rule
	FilePath   string  // File path where the secret was found
	LineNumber int     // Line number
	Column     int     // Column offset
	Match      string  // The matched text
	Severity   string  // Severity level from the rule
	Entropy    float64 // Shannon entropy of the match
	CommitHash string  // Git commit hash
	CommitMsg  string  // Git commit message
	Author     string  // Git author
	Date       string  // Commit date
}
