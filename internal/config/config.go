package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds persistent configuration for SecretScanner.
type Config struct {
	Format string   `yaml:"format"`
	Rules  string   `yaml:"rules"`
	Ignore []string `yaml:"ignore"`
}

// Load reads .secretscannerrc from the given directory.
// Returns a zero-value Config if the file doesn't exist.
func Load(repoPath string) Config {
	path := repoPath + "/.secretscannerrc"
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}
	}
	return cfg
}
