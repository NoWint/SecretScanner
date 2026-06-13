package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/NoWint/SecretScanner/internal/config"
	"github.com/NoWint/SecretScanner/internal/git"
	"github.com/NoWint/SecretScanner/internal/ignore"
	"github.com/NoWint/SecretScanner/internal/report"
	"github.com/NoWint/SecretScanner/internal/rules"
)

var (
	scanFormat    string
	scanRules     string
	scanNoHistory bool
	scanStaged    bool
	scanQuiet     bool
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

		// Load config file if exists
		cfg := config.Load(path)

		// Apply config defaults (CLI flags override config)
		if !cmd.Flags().Changed("format") && cfg.Format != "" {
			scanFormat = cfg.Format
		}
		if !cmd.Flags().Changed("rules") && cfg.Rules != "" {
			scanRules = cfg.Rules
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
		// Merge config allowlist into ignore patterns
		patterns = append(patterns, cfg.Ignore...)
		matcher := ignore.NewMatcher(patterns)

		// Progress callback
		var progress git.ProgressFunc
		if !scanQuiet && !scanStaged && !scanNoHistory {
			progress = func(scanned int) {
				fmt.Fprintf(os.Stderr, "\rScanning commits... %d", scanned)
			}
		}

		// Scan
		var findings []rules.Finding
		if scanStaged {
			findings, err = git.ScanStagedFiles(path, ruleSet, nil)
		} else if scanNoHistory {
			findings, err = git.ScanWorkingDirectory(path, ruleSet, nil)
		} else {
			findings, err = git.ScanRepository(path, ruleSet, progress)
		}

		if progress != nil {
			fmt.Fprintln(os.Stderr, "\rScanning commits... done!    ")
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
	scanCmd.Flags().BoolVarP(&scanQuiet, "quiet", "q", false, "Suppress progress output")
}
