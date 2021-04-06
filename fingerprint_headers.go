package wappalyzer

import (
	"strings"
)

// checkHeaders checks if the headers for a target match the fingerprints
// and returns the matched IDs if any.
func (s *Wappalyze) checkHeaders(headers map[string]string) []string {
	technologies := s.fingerprints.matchMapString(headers, headersPart)
	return technologies
}

// normalizeHeaders normalizes the headers for the tech discovery on headers
func (s *Wappalyze) normalizeHeaders(headers map[string]string) map[string]string {
	normalized := make(map[string]string, len(headers))

	for header, value := range headers {
		normalized[strings.ToLower(header)] = strings.ToLower(value)
	}
	return normalized
}
