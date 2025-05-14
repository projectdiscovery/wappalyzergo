package wappalyzer

import (
	"fmt"
	"strings"
	"testing"

	regexputil "github.com/projectdiscovery/utils/regexp"
)

func BenchmarkEvaluatePattern(b *testing.B) {
	patternStr := `Version/(\d{1,100}\.\d{1,100}\.\d{1,100})`

	enginesToTest := []struct {
		Name   string
		Engine regexputil.EngineType // User updated to EngineType
	}{
		{"Standard", regexputil.EngineStandard}, // User updated
		{"Regexp2", regexputil.EngineRegexp2},
		{"RE2", regexputil.EngineRE2}, // User added
	}

	inputSizes := []int{100, 1000, 10000, 100000} // 100B, 1KB, 10KB, 100KB

	for _, engineConfig := range enginesToTest {
		ec := engineConfig // Capture range variable
		b.Run(ec.Name, func(b *testing.B) {
			parsedPattern, err := ParsePattern(patternStr)
			if err != nil {
				b.Fatalf("Failed to parse pattern '%s': %v", patternStr, err)
			}
			for _, size := range inputSizes {
				s := size // Capture range variable
				b.Run(fmt.Sprintf("InputSize%d", s), func(b *testing.B) {
					var sb strings.Builder
					sb.Grow(s)
					matchStr := " Version/1.2.3"
					paddingSize := s - len(matchStr)
					if paddingSize < 0 {
						paddingSize = 0
					}
					for i := 0; i < paddingSize; i++ {
						sb.WriteByte('a')
					}
					sb.WriteString(matchStr)
					target := sb.String()

					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_, _ = parsedPattern.Evaluate(target)
					}
				})
			}
		})
	}
}
