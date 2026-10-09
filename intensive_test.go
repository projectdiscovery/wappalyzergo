package wappalyzer

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestIntensiveMixedPatterns loads a large page with the literals of the
// heaviest HTML and script patterns, so those regexps actually run. The
// detected technologies must match a client with the prefilter removed.
func TestIntensiveMixedPatterns(t *testing.T) {
	fast, err := New()
	if err != nil {
		t.Fatal(err)
	}
	slow, err := New()
	if err != nil {
		t.Fatal(err)
	}
	stripPrefilter(slow)

	headers := mixedHeaders(fast)
	for _, size := range []int{64 << 10, 256 << 10} {
		for _, dense := range []bool{false, true} {
			body := mixedExpensivePage(fast, size, dense)
			got := fast.Fingerprint(headers, body)
			want := slow.Fingerprint(headers, body)
			if !sameApps(got, want) {
				t.Fatalf("size %d dense %v mismatch\n got %v\nwant %v", size, dense, appNames(got), appNames(want))
			}

			folded := strings.ToLower(string(body))
			htmlHits := len(fast.fingerprints.htmlIndex.matching(folded))
			fastMedian := medianDuration(sampleFingerprint(fast, headers, body, 3))
			slowMedian := medianDuration(sampleFingerprint(slow, headers, body, 3))
			label := "sparse"
			if dense {
				label = "dense"
			}
			t.Logf("%s %dKB htmlCandidates %d apps %d prefilter %s regex %s speedup %.2fx",
				label, size>>10, htmlHits, len(got), fastMedian, slowMedian,
				float64(slowMedian)/float64(fastMedian))
		}
	}
}

// TestIntensiveHardCorpus plants every HTML needle, then makes the regexps
// work for it: needles at the end of a long body, non-ASCII filler, a storm
// of script URLs, and the same pages in uppercase.
func TestIntensiveHardCorpus(t *testing.T) {
	fast, err := New()
	if err != nil {
		t.Fatal(err)
	}
	slow, err := New()
	if err != nil {
		t.Fatal(err)
	}
	stripPrefilter(slow)
	headers := mixedHeaders(fast)
	needles := allHTMLNeedles(fast)

	cases := []struct {
		name string
		body []byte
	}{
		{"tail-256KB", pageWithTail(needles, 256<<10, []byte(" zzz "))},
		{"tail-1MB", pageWithTail(needles, 1<<20, []byte(" zzz "))},
		{"highbyte-256KB", pageWithTail(needles, 256<<10, []byte{0xff, 'z', 'z', 'z'})},
		{"upper-256KB", bytes.ToUpper(pageWithTail(needles, 256<<10, []byte(" zzz ")))},
		{"scripts-400", scriptStorm(fast, 400)},
	}
	for _, tc := range cases {
		got := fast.Fingerprint(headers, tc.body)
		want := slow.Fingerprint(headers, tc.body)
		if !sameApps(got, want) {
			t.Fatalf("%s mismatch\n got %v\nwant %v", tc.name, appNames(got), appNames(want))
		}
		folded := strings.ToLower(string(tc.body))
		htmlHits := len(fast.fingerprints.htmlIndex.matching(folded))
		fastD := medianDuration(sampleFingerprint(fast, headers, tc.body, 1))
		slowD := medianDuration(sampleFingerprint(slow, headers, tc.body, 1))
		t.Logf("%s bytes %d htmlCandidates %d apps %d prefilter %s regex %s speedup %.2fx",
			tc.name, len(tc.body), htmlHits, len(got), fastD, slowD, float64(slowD)/float64(fastD))
	}

	tail := pageWithTail(needles, 256<<10, []byte(" zzz "))
	for _, line := range slowestHTMLRegexes(fast, string(tail), 8) {
		t.Logf("slow regex %s", line)
	}
}

func TestIntensiveConcurrent(t *testing.T) {
	client, err := New()
	if err != nil {
		t.Fatal(err)
	}
	headers := mixedHeaders(client)
	body := pageWithTail(allHTMLNeedles(client), 256<<10, []byte(" zzz "))
	base := client.Fingerprint(headers, body)

	const workers = 8
	const rounds = 4
	var wg sync.WaitGroup
	failures := make(chan string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < rounds; j++ {
				got := client.Fingerprint(headers, body)
				if !sameApps(got, base) {
					failures <- "concurrent fingerprint changed"
					return
				}
			}
		}()
	}
	wg.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
}

func allHTMLNeedles(w *Wappalyze) string {
	var b strings.Builder
	b.WriteString("<div>")
	for _, fingerprint := range w.fingerprints.Apps {
		for _, pattern := range fingerprint.html {
			for _, group := range pattern.literals {
				for _, lit := range group {
					b.WriteString(lit)
					b.WriteByte('\n')
				}
			}
		}
	}
	b.WriteString("</div>")
	return b.String()
}

func pageWithTail(tail string, size int, filler []byte) []byte {
	if len(tail) >= size {
		return []byte(tail[:size])
	}
	buf := bytes.Repeat(filler, size/len(filler)+1)
	buf = buf[:size]
	copy(buf[size-len(tail):], tail)
	return buf
}

func scriptStorm(w *Wappalyze, limit int) []byte {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head>")
	count := 0
	for _, fingerprint := range w.fingerprints.Apps {
		for _, pattern := range fingerprint.scriptSrc {
			lit := firstLongLiteral(pattern)
			if lit == "" {
				continue
			}
			fmt.Fprintf(&b, `<script src="https://cdn.example/%s"></script>`, lit)
			count++
			if count == limit {
				b.WriteString("</head><body>zzz</body></html>")
				return []byte(b.String())
			}
		}
	}
	b.WriteString("</head><body>zzz</body></html>")
	return []byte(b.String())
}

func slowestHTMLRegexes(w *Wappalyze, body string, limit int) []string {
	folded := strings.ToLower(body)
	type timed struct {
		cost    time.Duration
		pattern string
	}
	var runs []timed
	for _, fingerprint := range w.fingerprints.Apps {
		for _, pattern := range fingerprint.html {
			if pattern == nil || pattern.regex == nil || pattern.SkipRegex {
				continue
			}
			if len(pattern.literals) > 0 && !literalsPresent(folded, pattern.literals) {
				continue
			}
			start := time.Now()
			_ = pattern.regex.FindStringSubmatch(body)
			runs = append(runs, timed{time.Since(start), pattern.regex.String()})
		}
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].cost > runs[j].cost })
	if len(runs) > limit {
		runs = runs[:limit]
	}
	lines := make([]string, len(runs))
	for i, run := range runs {
		text := run.pattern
		if len(text) > 140 {
			text = text[:140] + "..."
		}
		lines[i] = fmt.Sprintf("%s %s", run.cost, text)
	}
	return lines
}

func sampleFingerprint(w *Wappalyze, headers map[string][]string, body []byte, n int) []time.Duration {
	samples := make([]time.Duration, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		benchmarkFingerprintResult = w.Fingerprint(headers, body)
		samples[i] = time.Since(start)
	}
	return samples
}

func mixedHeaders(w *Wappalyze) map[string][]string {
	// Keys are already lowercase. normalizeHeaders folds names, so a second
	// "Content-Type" would overwrite this value in map iteration order.
	headers := map[string][]string{
		"content-type": {"text/html; charset=utf-8"},
	}
	for _, fingerprint := range w.fingerprints.Apps {
		for name, pattern := range fingerprint.headers {
			key := strings.ToLower(name)
			if _, exists := headers[key]; exists || pattern == nil {
				continue
			}
			value := "1"
			if len(pattern.literals) > 0 && len(pattern.literals[0]) > 0 {
				value = pattern.literals[0][0]
			}
			headers[key] = []string{value}
			if len(headers) >= 24 {
				return headers
			}
		}
	}
	return headers
}

func mixedExpensivePage(w *Wappalyze, size int, dense bool) []byte {
	var htmlPatterns []*ParsedPattern
	var scriptPatterns []*ParsedPattern
	for _, fingerprint := range w.fingerprints.Apps {
		htmlPatterns = append(htmlPatterns, fingerprint.html...)
		scriptPatterns = append(scriptPatterns, fingerprint.scriptSrc...)
	}
	sortByCost(htmlPatterns)
	sortByCost(scriptPatterns)

	var b strings.Builder
	b.WriteString("<!doctype html><html><head>")
	scripts := 0
	for _, pattern := range scriptPatterns {
		lit := firstLongLiteral(pattern)
		if lit == "" {
			continue
		}
		fmt.Fprintf(&b, `<script src="https://cdn.example/%s"></script>`, lit)
		scripts++
		if scripts == 48 {
			break
		}
	}
	b.WriteString("</head><body>")
	added := 0
	for _, pattern := range htmlPatterns {
		if len(pattern.literals) == 0 {
			continue
		}
		for _, group := range pattern.literals {
			b.WriteString("<div>")
			b.WriteString(strings.Join(group, " "))
			b.WriteString("</div>")
		}
		added++
		if added == 180 {
			break
		}
	}
	b.WriteString("</body></html>")
	page := b.String()
	if dense {
		var repeated strings.Builder
		for repeated.Len() < size {
			repeated.WriteString(page)
		}
		page = repeated.String()
	}
	const filler = " zzz "
	for len(page) < size {
		page += filler
	}
	if len(page) > size {
		page = page[:size]
	}
	return []byte(page)
}

func sortByCost(patterns []*ParsedPattern) {
	sort.Slice(patterns, func(i, j int) bool {
		return patternCost(patterns[i]) > patternCost(patterns[j])
	})
}

func patternCost(pattern *ParsedPattern) int {
	if pattern == nil || pattern.regex == nil {
		return 0
	}
	text := pattern.regex.String()
	return strings.Count(text, "{0,250}")*20 + strings.Count(text, "{1,250}")*20 + len(text)
}

func firstLongLiteral(pattern *ParsedPattern) string {
	if pattern == nil {
		return ""
	}
	best := ""
	for _, group := range pattern.literals {
		for _, lit := range group {
			if len(lit) > len(best) {
				best = lit
			}
		}
	}
	if len(best) < 8 {
		return ""
	}
	return best
}
