package scanner

import (
	"math"
	"testing"
)

func TestShannonEntropyEmpty(t *testing.T) {
	got := ShannonEntropy("")
	if got != 0 {
		t.Errorf("expected 0 for empty string, got %f", got)
	}
}

func TestShannonEntropySingleChar(t *testing.T) {
	got := ShannonEntropy("aaaa")
	if got != 0 {
		t.Errorf("expected 0 for single repeated char, got %f", got)
	}
}

func TestShannonEntropyUniform(t *testing.T) {
	got := ShannonEntropy("ab")
	if math.Abs(got-1.0) > 0.01 {
		t.Errorf("expected ~1.0 for 'ab', got %f", got)
	}
}

func TestShannonEntropyHighEntropy(t *testing.T) {
	got := ShannonEntropy("AKIA3E8F9Z7XMQ2P4L6")
	if got < 3.5 {
		t.Errorf("expected entropy > 3.5 for mixed string, got %f", got)
	}
}

func TestShannonEntropyMax(t *testing.T) {
	got := ShannonEntropy("0123456789abcdef")
	if got < 3.0 {
		t.Errorf("expected entropy > 3.0 for hex string, got %f", got)
	}
}
