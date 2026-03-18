package wappalyzer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSplitParts(t *testing.T) {
	tests := []struct {
		input    string
		expected []int
	}{
		{"1.2.3", []int{1, 2, 3}},
		{"10.0.1", []int{10, 0, 1}},
		{"3", []int{3}},
		{"", []int{}},
		{"abc", []int{0}},
		{"1.2.beta", []int{1, 2, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			require.Equal(t, tt.expected, splitParts(tt.input))
		})
	}
}

func TestVersionLess(t *testing.T) {
	tests := []struct {
		a, b     string
		expected bool
	}{
		{"1.0.0", "2.0.0", true},
		{"2.0.0", "1.0.0", false},
		{"1.0.0", "1.0.0", false},
		{"1.0.0", "1.0.1", true},
		{"3", "3.6.0", true},
		{"3.6.0", "3", false},
		{"1.2", "1.10", true},
	}
	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			require.Equal(t, tt.expected, versionLess(tt.a, tt.b))
		})
	}
}

func TestIsMoreSpecific(t *testing.T) {
	tests := []struct {
		name     string
		a, b     string
		expected bool
	}{
		{"more segments wins", "3.6.0", "3", true},
		{"fewer segments loses", "3", "3.6.0", false},
		{"same segments higher wins", "3.6.0", "3.5.0", true},
		{"same segments lower loses", "3.5.0", "3.6.0", false},
		{"equal versions", "1.2.3", "1.2.3", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, isMoreSpecific(tt.a, tt.b))
		})
	}
}

func TestVersionSelectionInFingerprinting(t *testing.T) {
	wappalyzer, err := New()
	require.NoError(t, err)

	t.Run("deterministic header version", func(t *testing.T) {
		var results []map[string]struct{}
		for i := 0; i < 20; i++ {
			matches := wappalyzer.Fingerprint(map[string][]string{
				"Server": {"Apache/2.4.29"},
			}, []byte(""))
			results = append(results, matches)
		}
		for i := 1; i < len(results); i++ {
			require.Equal(t, results[0], results[i], "fingerprinting should be deterministic across runs")
		}
	})
}
