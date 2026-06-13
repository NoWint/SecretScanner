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
		// Directory pattern (trailing /)
		if strings.HasSuffix(pattern, "/") {
			dirName := strings.TrimSuffix(pattern, "/")
			// Match at any depth: docs/ matches both docs/ and src/docs/
			if filePath == dirName || strings.HasPrefix(filePath, dirName+"/") || strings.Contains(filePath, "/"+dirName+"/") {
				return true
			}
			continue
		}
		// Extension pattern (*.ext)
		if strings.HasPrefix(pattern, "*.") {
			ext := pattern[1:] // *.lock -> .lock
			if strings.HasSuffix(filePath, ext) {
				return true
			}
			continue
		}
		// Exact match or glob
		matched, _ := filepath.Match(pattern, filepath.Base(filePath))
		if matched {
			return true
		}
	}
	return false
}
