package rules

import (
	"fmt"
	"os"
	"regexp"

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
		if yr.Pattern == "" {
			return nil, fmt.Errorf("rule %s has empty pattern", yr.ID)
		}
		if _, err := regexp.Compile(yr.Pattern); err != nil {
			return nil, fmt.Errorf("rule %s has invalid regex pattern %q: %w", yr.ID, yr.Pattern, err)
		}
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
