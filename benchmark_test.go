package wappalyzer

import "testing"

var benchmarkFingerprintResult map[string]struct{}

func BenchmarkFingerprintPassive(b *testing.B) {
	wappalyzer, err := New()
	if err != nil {
		b.Fatal(err)
	}

	headers := map[string][]string{
		"Content-Type": {"text/html; charset=utf-8"},
		"Server":       {"Apache/2.4.62"},
		"Set-Cookie":   {"jsessionid=example; Path=/"},
	}
	body := []byte(`<!doctype html><html><head><meta name="generator" content="WordPress 6.8"><script src="/wp-includes/js/jquery.min.js"></script></head><body class="wordpress"></body></html>`)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkFingerprintResult = wappalyzer.Fingerprint(headers, body)
	}
}
