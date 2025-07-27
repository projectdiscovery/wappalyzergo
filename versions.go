package wappalyzer

import (
	"strconv"
	"strings"
)

// Lowest returns the lowest version from a slice of version strings.
// Supports colon- and dot-separated numeric versions (e.g. "1:2:0" or "1.2.0").
// Non-numeric segments are treated as zero. If no valid version is found,
// it returns the empty string.
func Lowest(versions []string) string {
	var lowest string
	for _, v := range versions {
		if v == "" {
			continue // skip blank entries
		}
		if lowest == "" || versionLess(v, lowest) {
			lowest = v
		}
	}
	return lowest
}

// versionLess reports whether version a < version b.
func versionLess(a, b string) bool {
	aParts := splitParts(a)
	bParts := splitParts(b)

	// Compare segment by segment
	max := len(aParts)
	if len(bParts) > max {
		max = len(bParts)
	}
	for i := 0; i < max; i++ {
		ai := 0
		bi := 0
		if i < len(aParts) {
			ai = aParts[i]
		}
		if i < len(bParts) {
			bi = bParts[i]
		}
		if ai < bi {
			return true
		}
		if ai > bi {
			return false
		}
	}
	// they are equal
	return false
}

// splitParts splits v on ':' or '.' and parses each piece as an integer.
// Non‑numeric or empty pieces become zero.
func splitParts(v string) []int {
	fields := strings.FieldsFunc(v, func(r rune) bool {
		return r == ':' || r == '.'
	})
	parts := make([]int, len(fields))
	for i, f := range fields {
		if n, err := strconv.Atoi(f); err == nil {
			parts[i] = n
		} else {
			parts[i] = 0
		}
	}
	return parts
}
