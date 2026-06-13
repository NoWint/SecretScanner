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
		if strings.HasSuffix(pattern, "/") {
			if strings.HasPrefix(filePath, pattern) || strings.HasPrefix(filePath, strings.TrimSuffix(pattern, "/")+"/") {
				return true
			}
			continue
		}
		if strings.HasPrefix(pattern, "*.") {
			ext := pattern[1:]
			if strings.HasSuffix(filePath, ext) {
				return true
			}
			continue
		}
		matched, _ := filepath.Match(pattern, filepath.Base(filePath))
		if matched {
			return true
		}
	}
	return false
}
