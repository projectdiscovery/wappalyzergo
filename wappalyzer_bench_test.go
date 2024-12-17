package wappalyzer

import (
	"crypto/rand"
	"fmt"
	"testing"

	randutil "github.com/projectdiscovery/utils/rand"
	"github.com/stretchr/testify/require"
)

// generateRandomData creates random HTTP headers and body for testing
func generateRandomData() (map[string][]string, []byte, error) {
	headers := make(map[string][]string)
	headerCount, err := randutil.IntN(50)
	if err != nil {
		return nil, nil, err
	}

	headerCount += 50

	for i := 0; i < headerCount; i++ {
		headerNameI, err := randutil.IntN(20)
		if err != nil {
			return nil, nil, err
		}
		headerName := make([]byte, headerNameI+20)
		headerValueI, err := randutil.IntN(80)
		if err != nil {
			return nil, nil, err
		}
		headerValue := make([]byte, headerValueI+60)
		if _, err := rand.Read(headerName); err != nil {
			return nil, nil, err
		}
		if _, err := rand.Read(headerValue); err != nil {
			return nil, nil, err
		}
		headers[fmt.Sprintf("X-Header-%x", headerName)] = []string{fmt.Sprintf("%x", headerValue)}
	}

	commonHeaderServerI, err := randutil.IntN(3)
	if err != nil {
		return nil, nil, err
	}
	headers["Server"] = []string{[]string{"Apache", "nginx", "IIS"}[commonHeaderServerI]}
	headers["Content-Type"] = []string{"text/html"}
	commonHeaderPoweredByI, err := randutil.IntN(3)
	if err != nil {
		return nil, nil, err
	}
	headers["X-Powered-By"] = []string{[]string{"PHP/7.4", "ASP.NET", "Express"}[commonHeaderPoweredByI]}

	// Generate large random body
	bodySizeI, err := randutil.IntN(1024 * 1024)
	if err != nil {
		return nil, nil, err
	}
	bodySize := 1024*1024 + bodySizeI
	randomBody := make([]byte, bodySize)
	if _, err := rand.Read(randomBody); err != nil {
		return nil, nil, err
	}

	html := fmt.Sprintf(`<!DOCTYPE html><html><head><title>%x</title></head><body>%x</body></html>`,
		randomBody[:100], randomBody[100:])

	return headers, []byte(html), nil
}

func BenchmarkWappalyzer(b *testing.B) {
	wappalyzer, err := New()
	require.Nil(b, err, "could not create wappalyzer")

	// Generate test data once before starting the benchmark
	headers, body, err := generateRandomData()
	require.Nil(b, err, "could not generate random data")

	b.ResetTimer()
	b.SetParallelism(1) // Ensure single thread for cleaner profile

	for i := 0; i < b.N; i++ {
		wappalyzer.Fingerprint(headers, body)
	}
}
