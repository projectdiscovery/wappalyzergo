package wappalyzer

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"testing"

	regexputil "github.com/projectdiscovery/utils/regexp"
	"github.com/stretchr/testify/require"
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

// Helper constant and functions for random data generation
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// generateRandomBody creates a random byte slice of a given size.
func generateRandomBody(n int) []byte {
	b := make([]byte, n)
	// No need to seed here, rand.Seed should be called once per test run or benchmark setup.
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return b
}

// generateRandomHeaders creates a somewhat realistic http.Header map.
func generateRandomHeaders() http.Header {
	headers := make(http.Header)
	commonKeys := []string{
		"Server", "X-Powered-By", "Content-Type", "X-AspNet-Version", "X-AspNetMvc-Version",
		"User-Agent", "Accept-Language", "Referer", "Cookie", "Authorization", "X-Request-ID",
	}

	rand.Shuffle(len(commonKeys), func(i, j int) { commonKeys[i], commonKeys[j] = commonKeys[j], commonKeys[i] })
	numHeadersToSet := rand.Intn(len(commonKeys)/2) + 3 // Set 3 to len/2 + 2 headers

	for i := 0; i < numHeadersToSet && i < len(commonKeys); i++ {
		key := commonKeys[i]
		var value string
		switch key {
		case "Content-Type":
			contentTypes := []string{"text/html; charset=utf-8", "application/json", "application/xml", "text/javascript", "text/css", "application/x-www-form-urlencoded"}
			value = contentTypes[rand.Intn(len(contentTypes))]
		case "Server":
			servers := []string{"Apache", "nginx", "IIS", "LiteSpeed", "Caddy", "Envoy"}
			value = fmt.Sprintf("%s/%d.%d.%d", servers[rand.Intn(len(servers))], rand.Intn(5)+1, rand.Intn(20), rand.Intn(10))
		case "X-Powered-By":
			poweredBy := []string{"PHP/8.1.5", "ASP.NET", "Express", "Ruby/3.0.1", "Python/3.9", "Java/17"}
			value = poweredBy[rand.Intn(len(poweredBy))]
		case "User-Agent":
			userAgents := []string{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36",
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15",
				"Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.101 Mobile Safari/537.36",
			}
			value = userAgents[rand.Intn(len(userAgents))]
		case "Accept-Language":
			value = "en-US,en;q=0.9,es;q=0.8"
		default:
			valueLength := rand.Intn(30) + 10 // Length 10-39
			valRunes := make([]rune, valueLength)
			for k := range valRunes {
				valRunes[k] = rune(letterBytes[rand.Intn(len(letterBytes))])
			}
			value = string(valRunes)
		}
		headers.Set(key, value)
	}

	// Chance to add Set-Cookie header
	if rand.Intn(2) == 0 { // 50% chance
		cookieName := "session_id"
		if rand.Intn(3) == 0 {
			cookieName = fmt.Sprintf("app_token_%d", rand.Intn(100))
		}
		valueLength := rand.Intn(40) + 20 // Length 20-59
		valRunes := make([]rune, valueLength)
		for k := range valRunes {
			valRunes[k] = rune(letterBytes[rand.Intn(len(letterBytes))])
		}
		cookieValue := string(valRunes)

		cookieParts := []string{fmt.Sprintf("%s=%s", cookieName, cookieValue)}
		if rand.Intn(2) == 0 {
			cookieParts = append(cookieParts, "Path=/")
		}
		if rand.Intn(2) == 0 {
			cookieParts = append(cookieParts, "HttpOnly")
		}
		if rand.Intn(3) == 0 && headers.Get("Content-Type") != "" && strings.Contains(headers.Get("Content-Type"), "html") { // Secure only if looks like HTTPS could be used
			cookieParts = append(cookieParts, "Secure")
		}
		if rand.Intn(3) == 0 {
			cookieParts = append(cookieParts, fmt.Sprintf("Max-Age=%d", rand.Intn(7200)+600))
		} // Max-Age between 10min and 2h10min
		if rand.Intn(4) == 0 {
			samesiteOpts := []string{"Strict", "Lax", "None"}
			cookieParts = append(cookieParts, "SameSite="+samesiteOpts[rand.Intn(len(samesiteOpts))])
			// If SameSite=None, Secure attribute is required by modern browsers
			if strings.HasSuffix(cookieParts[len(cookieParts)-1], "None") && !contains(cookieParts, "Secure") {
				cookieParts = append(cookieParts, "Secure")
			}
		}
		headers.Add("Set-Cookie", strings.Join(cookieParts, "; "))
	}
	return headers
}

// contains is a helper for string slices.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.Contains(s, item) { // Check if "Secure" is part of any attribute string
			return true
		}
	}
	return false
}

// BenchmarkEvaluateAllPatterns benchmarks the Fingerprint method
// using randomly generated headers and body content of increasing sizes.
func BenchmarkEvaluateAllPatterns(b *testing.B) {
	enginesToTest := []struct {
		Name   string
		Engine regexputil.EngineType
	}{
		{"Standard", regexputil.EngineStandard},
		{"Regexp2", regexputil.EngineRegexp2},
		{"RE2", regexputil.EngineRE2},
	}

	// Define various input sizes for the request body (e.g., 1KB, 8KB, 64KB, 128KB, 512KB)
	inputSizes := []int{1 * 1024, 8 * 1024, 64 * 1024, 128 * 1024, 512 * 1024}

	for _, engineConfig := range enginesToTest {
		ec := engineConfig // Capture range variable
		b.Run(ec.Name, func(b *testing.B) {
			// Set the global engine variable. New() will use this.
			engine = ec.Engine
			wp, err := New()
			require.Nil(b, err, "Failed to create wappalyzer instance for engine %s", ec.Name)

			for _, size := range inputSizes {
				s := size // Capture range variable
				// Create a sub-benchmark for each input size
				b.Run(fmt.Sprintf("InputSize_%dKB", s/1024), func(b *testing.B) {
					// Generate random headers and body for this specific sub-benchmark.
					// This data is generated once per (engine, size) combination,
					// outside the b.N loop, so its generation time doesn't affect the measurement.
					randomHeaders := generateRandomHeaders()
					randomBody := generateRandomBody(s)

					b.ResetTimer() // Start timing now, after setup
					for i := 0; i < b.N; i++ {
						// The actual operation to benchmark
						_ = wp.Fingerprint(randomHeaders, randomBody)
					}
				})
			}
		})
	}
}
