package wappalyzer

import "testing"

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
