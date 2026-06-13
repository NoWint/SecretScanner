package scanner

import (
	"math"
)

// ShannonEntropy calculates the Shannon entropy of a string.
// Returns a value between 0 and 8, where higher values indicate
// more randomness (likely a generated secret).
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}
