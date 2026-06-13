package ignore

import (
	"testing"
)

func TestLoadIgnorePatterns(t *testing.T) {
	patterns := []string{"*.lock", "vendor/", "node_modules/"}
	matcher := NewMatcher(patterns)

	if !matcher.Match("package.lock") {
		t.Error("expected *.lock to match package.lock")
	}
	if !matcher.Match("vendor/main.go") {
		t.Error("expected vendor/ to match vendor/main.go")
	}
	if !matcher.Match("node_modules/react/index.js") {
		t.Error("expected node_modules/ to match node_modules/react/index.js")
	}
	if matcher.Match("src/main.go") {
		t.Error("expected src/main.go not to match any pattern")
	}
}

func TestLoadIgnorePatternsEmpty(t *testing.T) {
	matcher := NewMatcher(nil)
	if matcher.Match("anything.go") {
		t.Error("empty matcher should not match anything")
	}
}
