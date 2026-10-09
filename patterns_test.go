package wappalyzer

import (
	"sort"
	"strings"
	"testing"
)

func TestParsePattern(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedRegex string
		expectedConf  int
		expectedVer   string
		expectError   bool
	}{
		{
			name:          "Basic pattern",
			input:         "Mage.*",
			expectedRegex: "(?i)Mage.{0,250}",
			expectedConf:  100,
		},
		{
			name:          "With confidence",
			input:         "Mage.*\\;confidence:50",
			expectedRegex: "(?i)Mage.{0,250}",
			expectedConf:  50,
		},
		{
			name:          "With version",
			input:         "jquery-([0-9.]+)\\.js\\;version:\\1",
			expectedRegex: "(?i)jquery-([0-9.]{1,250})\\.js",
			expectedConf:  100,
			expectedVer:   "\\1",
		},
		{
			name:          "Complex pattern - 1",
			input:         "/wp-content/themes/make(?:-child)?/.+frontend\\.js(?:\\?ver=(\\d+(?:\\.\\d+)+))?\\;version:\\1",
			expectedRegex: `(?i)/wp-content/themes/make(?:-child)?/.{1,250}frontend\.js(?:\?ver=(\d{1,20}(?:\.\d{1,20}){1,20}))?`,
			expectedConf:  100,
			expectedVer:   "\\1",
		},
		{
			name:          "Complex pattern - 2",
			input:         "(?:((?:\\d+\\.)+\\d+)\\/)?chroma(?:\\.min)?\\.js\\;version:\\1",
			expectedRegex: `(?i)(?:((?:\d{1,20}\.){1,20}\d{1,20})\/)?chroma(?:\.min)?\.js`,
			expectedConf:  100,
			expectedVer:   "\\1",
		},
		{
			name:          "Complex pattern - 3",
			input:         "(?:((?:\\d+\\.)+\\d+)\\/(?:dc\\/)?)?dc(?:\\.leaflet)?\\.js\\;version:\\1",
			expectedRegex: `(?i)(?:((?:\d{1,20}\.){1,20}\d{1,20})\/(?:dc\/)?)?dc(?:\.leaflet)?\.js`,
			expectedConf:  100,
			expectedVer:   "\\1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern, err := ParsePattern(tt.input)
			if (err != nil) != tt.expectError {
				t.Errorf("parsePattern() error = %v, expectError %v", err, tt.expectError)
				return
			}
			if err == nil {
				if pattern.regex.String() != tt.expectedRegex {
					t.Errorf("Expected regex = %s, got %s", tt.expectedRegex, pattern.regex.String())
				}
				if pattern.Confidence != tt.expectedConf {
					t.Errorf("Expected confidence = %d, got %d", tt.expectedConf, pattern.Confidence)
				}
				if pattern.Version != tt.expectedVer {
					t.Errorf("Expected version = %s, got %s", tt.expectedVer, pattern.Version)
				}
			}
		})
	}
}
func TestExtractVersion(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		target      string
		expectedVer string
		expectError bool
	}{
		{
			name:        "Simple version extraction",
			pattern:     "Mage ([0-9.]+)\\;version:\\1",
			target:      "Mage 2.3",
			expectedVer: "2.3",
			expectError: false,
		},
		{
			name:        "Version with ternary - true",
			pattern:     "Mage ([0-9.]+)\\;version:\\1?found:",
			target:      "Mage 2.3",
			expectedVer: "found",
			expectError: false,
		},
		{
			name:        "Version with ternary - false",
			pattern:     "Mage\\;version:\\1?:not found",
			target:      "Mage",
			expectedVer: "not found",
			expectError: false,
		},
		{
			name:        "First version pattern",
			pattern:     "Mage ([0-9.]+)\\;version:\\1?a:",
			target:      "Mage 2.3",
			expectedVer: "a",
			expectError: false,
		},
		{
			name:        "Complex pattern",
			pattern:     "([\\d.]+)?/modernizr(?:\\.([\\d.]+))?.*\\.js\\;version:\\1?\\1:\\2",
			target:      "2.6.2/modernizr.js",
			expectedVer: "2.6.2",
			expectError: false,
		},
		{
			name:        "Complex pattern - 2",
			pattern:     "([\\d.]+)?/modernizr(?:\\.([\\d.]+))?.*\\.js\\;version:\\1?\\1:\\2",
			target:      "/modernizr.2.5.7.js",
			expectedVer: "2.5.7",
			expectError: false,
		},
		{
			name:        "Complex pattern - 3",
			pattern:     "(?:apache(?:$|/([\\d.]+)|[^/-])|(?:^|\\b)httpd)\\;version:\\1",
			target:      "apache",
			expectError: false,
		},
		{
			name:        "Complex pattern - 4",
			pattern:     "(?:apache(?:$|/([\\d.]+)|[^/-])|(?:^|\\b)httpd)\\;version:\\1",
			target:      "apache/2.4.29",
			expectedVer: "2.4.29",
			expectError: false,
		},
		{
			name:        "Complex pattern - 5",
			pattern:     "/wp-content/themes/make(?:-child)?/.+frontend\\.js(?:\\?ver=(\\d+(?:\\.\\d+)+))?\\;version:\\1",
			target:      "/wp-content/themes/make-child/whatever/frontend.js?ver=1.9.1",
			expectedVer: "1.9.1",
			expectError: false,
		},
		{
			name:        "Complex pattern - 6",
			pattern:     "(?:((?:\\d+\\.)+\\d+)\\/)?chroma(?:\\.min)?\\.js\\;version:\\1",
			target:      "/ajax/libs/chroma-js/2.4.2/chroma.min.js",
			expectedVer: "2.4.2",
			expectError: false,
		},
		{
			name:        "Complex pattern - 7",
			pattern:     "(?:((?:\\d+\\.)+\\d+)\\/(?:dc\\/)?)?dc(?:\\.leaflet)?\\.js\\;version:\\1",
			target:      "/ajax/libs/dc/2.1.8/dc.leaflet.js",
			expectedVer: "2.1.8",
			expectError: false,
		},
		{
			name:        "Complex pattern - 8",
			pattern:     "(?:(\\d+(?:\\.\\d+)+)\\/(?:dc\\/)?)?dc(?:\\.leaflet)?\\.js\\;version:\\1",
			target:      "/ajax/libs/dc/2.1.8/dc.leaflet.js",
			expectedVer: "2.1.8",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ParsePattern(tt.pattern)
			if err != nil {
				t.Fatal("Failed to parse pattern:", err)
			}

			match, ver := p.Evaluate(tt.target)
			if !match {
				t.Errorf("Failed to match pattern %s with target %s", tt.pattern, tt.target)
				return
			}
			if (err != nil) != tt.expectError {
				t.Errorf("extractVersion() error = %v, expectError %v", err, tt.expectError)
				return
			}
			if ver != tt.expectedVer {
				t.Errorf("Expected version = %s, got %s", tt.expectedVer, ver)
			}
		})
	}
}

func TestLiteralPrefilter(t *testing.T) {
	either, err := ParsePattern("foo|bar")
	if err != nil {
		t.Fatal(err)
	}
	if !sameLiteralGroups(either.literals, [][]string{{"foo"}, {"bar"}}) {
		t.Fatalf("alternation literals = %q", either.literals)
	}
	if ok, _ := either.Evaluate("BAR"); !ok {
		t.Fatal("alternation missed BAR")
	}
	if ok, _ := either.Evaluate("zzz"); ok {
		t.Fatal("alternation matched unrelated text")
	}

	// A branch with no usable needle must disable the whole prefilter.
	// Otherwise "A" would be skipped and the result would be lossy.
	uncovered, err := ParsePattern("foo|a")
	if err != nil {
		t.Fatal(err)
	}
	if len(uncovered.literals) != 0 {
		t.Fatalf("short branch should disable the prefilter, got %q", uncovered.literals)
	}
	if ok, _ := uncovered.Evaluate("A"); !ok {
		t.Fatal("short branch was dropped")
	}

	word, err := ParsePattern("WordPress")
	if err != nil {
		t.Fatal(err)
	}
	if !sameLiteralGroups(word.literals, [][]string{{"wordpress"}}) {
		t.Fatalf("literal = %q", word.literals)
	}
	if ok, _ := word.Evaluate("uses wordpress here"); !ok {
		t.Fatal("case-insensitive literal missed")
	}

	glued, err := ParsePattern("sh(?:core|brush|themedefault)")
	if err != nil {
		t.Fatal(err)
	}
	if !sameLiteralGroups(glued.literals, [][]string{{"shcore"}, {"shbrush"}, {"shthemedefault"}}) {
		t.Fatalf("glued literals = %q", glued.literals)
	}
	if ok, _ := glued.Evaluate("SHBRUSH"); !ok {
		t.Fatal("glued alternation missed SHBRUSH")
	}
	if ok, _ := glued.Evaluate("core"); ok {
		t.Fatal("glued alternation matched a fragment")
	}

	gap, err := ParsePattern(`wordpress[^>]{0,20}jquery`)
	if err != nil {
		t.Fatal(err)
	}
	if !sameLiteralGroups(gap.literals, [][]string{{"jquery", "wordpress"}}) {
		t.Fatalf("gap literals = %q", gap.literals)
	}
	if ok, _ := gap.Evaluate("wordpress only"); ok {
		t.Fatal("gap pattern matched one side")
	}
	if ok, _ := gap.Evaluate("WordPress x jquery"); !ok {
		t.Fatal("gap pattern missed both sides")
	}

	marked, err := ParsePattern("xenforo™|jquery.extend(true, xenforo)")
	if err != nil {
		t.Fatal(err)
	}
	if len(marked.literals) == 0 {
		t.Fatal("non-ASCII literal dropped the ASCII text")
	}
	if ok, _ := marked.Evaluate("forum software by xenforo™"); !ok {
		t.Fatal("non-ASCII literal missed")
	}
	if ok, _ := marked.Evaluate("no vendor here"); ok {
		t.Fatal("non-ASCII literal matched unrelated text")
	}
}

func sameLiteralGroups(got, want [][]string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := make(map[string]int, len(want))
	for _, group := range want {
		copied := append([]string{}, group...)
		sort.Strings(copied)
		seen[strings.Join(copied, "\x00")]++
	}
	for _, group := range got {
		copied := append([]string{}, group...)
		sort.Strings(copied)
		key := strings.Join(copied, "\x00")
		if seen[key] == 0 {
			return false
		}
		seen[key]--
	}
	return true
}

func TestLiteralPrefilterAgreesWithRegex(t *testing.T) {
	client, err := New()
	if err != nil {
		t.Fatal(err)
	}
	targets := []string{
		`<!doctype html><html><head><script src="/wp-includes/js/jquery.min.js"></script></head><body class="wordpress">WordPress</body></html>`,
		"https://cdn.example.com/wp-includes/js/jquery.min.js",
		"/static/app.js",
		"",
	}
	for name, fingerprint := range client.fingerprints.Apps {
		checkPatterns(t, name, fingerprint.html, targets)
		checkPatterns(t, name, fingerprint.scriptSrc, targets)
	}
}

func checkPatterns(t *testing.T, name string, patterns []*ParsedPattern, targets []string) {
	t.Helper()
	for _, pattern := range patterns {
		if pattern == nil || pattern.regex == nil {
			continue
		}
		cases := append([]string{}, targets...)
		for _, group := range pattern.literals {
			cases = append(cases, strings.Join(group, " "))
			for _, lit := range group {
				cases = append(cases, lit, strings.ToUpper(lit), "/*"+lit+"*/")
			}
		}
		for _, target := range cases {
			raw := len(pattern.regex.FindStringSubmatch(target)) > 0
			got, _ := pattern.Evaluate(target)
			if raw != got {
				t.Fatalf("%s pattern %s literals %q target %q: regex %v evaluate %v", name, pattern.regex.String(), pattern.literals, target, raw, got)
			}
		}
	}
}
