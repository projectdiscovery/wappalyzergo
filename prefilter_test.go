package wappalyzer

import (
	"sort"
	"strings"
	"testing"
	"time"
)

func TestBodyPatternsHavePrefilter(t *testing.T) {
	client, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for name, fingerprint := range client.fingerprints.Apps {
		requirePrefilter(t, name, fingerprint.html)
		requirePrefilter(t, name, fingerprint.scriptSrc)
	}
}

func requirePrefilter(t *testing.T, name string, patterns []*ParsedPattern) {
	t.Helper()
	for _, pattern := range patterns {
		if pattern == nil || pattern.SkipRegex || pattern.regex == nil {
			continue
		}
		if len(pattern.literals) == 0 {
			t.Errorf("%s has no safe prefilter: %s", name, pattern.regex.String())
		}
	}
}

func TestAhoOverlaps(t *testing.T) {
	automaton := newAho()
	automaton.add("he", 0)
	automaton.add("she", 1)
	automaton.add("his", 2)
	automaton.add("hers", 3)
	automaton.build()

	present := make([]bool, 4)
	automaton.visit("ushers", present)
	if !present[0] || !present[1] || present[2] || !present[3] {
		t.Fatalf("ushers hits = %v", present)
	}

	present = make([]bool, 4)
	automaton.visit("his", present)
	if present[0] || present[1] || !present[2] || present[3] {
		t.Fatalf("his hits = %v", present)
	}
}

func TestLiteralIndexMatchesContains(t *testing.T) {
	client, err := New()
	if err != nil {
		t.Fatal(err)
	}
	checkLiteralIndex(t, client.fingerprints.htmlIndex.matching, patternsOf(client, func(fp *CompiledFingerprint) []*ParsedPattern { return fp.html }))
	checkLiteralIndex(t, client.fingerprints.scriptIndex.matching, patternsOf(client, func(fp *CompiledFingerprint) []*ParsedPattern { return fp.scriptSrc }))
}

func checkLiteralIndex(t *testing.T, match func(string) map[*ParsedPattern]struct{}, patterns []*ParsedPattern) {
	t.Helper()
	haystacks := []string{"", "the quick brown fox jumps over the lazy dog"}
	for _, pattern := range patterns {
		for _, group := range pattern.literals {
			haystacks = append(haystacks, strings.Join(group, " "))
		}
	}
	for _, haystack := range haystacks {
		folded := strings.ToLower(haystack)
		got := match(folded)
		for _, pattern := range patterns {
			_, indexed := got[pattern]
			want := pattern.SkipRegex || len(pattern.literals) == 0 || literalsPresent(folded, pattern.literals)
			if indexed != want {
				t.Fatalf("index %v contains %v for %q in %q", indexed, want, pattern.literals, haystack)
			}
		}
	}
}

func TestFingerprintPrefilterAgrees(t *testing.T) {
	fast, err := New()
	if err != nil {
		t.Fatal(err)
	}
	slow, err := New()
	if err != nil {
		t.Fatal(err)
	}
	stripPrefilter(slow)

	headers := map[string][]string{
		"Content-Type": {"text/html; charset=utf-8"},
		"Server":       {"Apache/2.4.62"},
		"Set-Cookie":   {"jsessionid=example; Path=/"},
	}
	bodies := [][]byte{
		nil,
		[]byte(`<!doctype html><html><head><meta name="generator" content="WordPress 6.8"><script src="/wp-includes/js/jquery.min.js"></script></head><body class="wordpress">powered by phpmyadmin</body></html>`),
		realisticPage(8, 8<<10),
		realisticPage(4, 32<<10),
		[]byte(`<html><title>phpMyAdmin</title><link href="/phpmyadmin.css.php"><input name="csrfmiddlewaretoken"></html>`),
	}
	for _, body := range bodies {
		got := fast.Fingerprint(headers, body)
		want := slow.Fingerprint(headers, body)
		if !sameApps(got, want) {
			t.Fatalf("fingerprint mismatch\n got %v\nwant %v", appNames(got), appNames(want))
		}
	}

	wordpress := fast.Fingerprint(headers, bodies[1])
	if !hasApp(wordpress, "WordPress") {
		t.Fatalf("WordPress page apps = %v", appNames(wordpress))
	}
}

func TestFingerprintPrefilterFaster(t *testing.T) {
	fast, err := New()
	if err != nil {
		t.Fatal(err)
	}
	slow, err := New()
	if err != nil {
		t.Fatal(err)
	}
	stripPrefilter(slow)

	headers := map[string][]string{"Content-Type": {"text/html; charset=utf-8"}}
	body := realisticPage(8, 64<<10)
	if !sameApps(fast.Fingerprint(headers, body), slow.Fingerprint(headers, body)) {
		t.Fatal("speed sample changed fingerprint results")
	}

	const samples = 7
	fastTimes := make([]time.Duration, samples)
	slowTimes := make([]time.Duration, samples)
	for i := 0; i < samples; i++ {
		start := time.Now()
		benchmarkFingerprintResult = fast.Fingerprint(headers, body)
		fastTimes[i] = time.Since(start)

		start = time.Now()
		benchmarkFingerprintResult = slow.Fingerprint(headers, body)
		slowTimes[i] = time.Since(start)
	}
	fastMedian := medianDuration(fastTimes)
	slowMedian := medianDuration(slowTimes)
	// A full regexp scan of this page is much slower. 8x is the floor so a
	// loaded CI runner can be noisy without the speedup disappearing.
	const minSpeedup = 8.0
	speedup := float64(slowMedian) / float64(fastMedian)
	t.Logf("prefilter %s regex %s speedup %.2fx", fastMedian, slowMedian, speedup)
	if speedup < minSpeedup {
		t.Fatalf("prefilter speedup %.2fx (fast %s, regex %s), want at least %.1fx", speedup, fastMedian, slowMedian, minSpeedup)
	}
}

func patternsOf(client *Wappalyze, pick func(*CompiledFingerprint) []*ParsedPattern) []*ParsedPattern {
	var patterns []*ParsedPattern
	for _, fingerprint := range client.fingerprints.Apps {
		for _, pattern := range pick(fingerprint) {
			if pattern != nil {
				patterns = append(patterns, pattern)
			}
		}
	}
	return patterns
}

func sameApps(got, want map[string]struct{}) bool {
	if len(got) != len(want) {
		return false
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			return false
		}
	}
	return true
}

func hasApp(apps map[string]struct{}, name string) bool {
	if _, ok := apps[name]; ok {
		return true
	}
	prefix := name + ":"
	for key := range apps {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

func appNames(apps map[string]struct{}) []string {
	names := make([]string, 0, len(apps))
	for name := range apps {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func medianDuration(samples []time.Duration) time.Duration {
	copied := append([]time.Duration{}, samples...)
	sort.Slice(copied, func(i, j int) bool { return copied[i] < copied[j] })
	return copied[len(copied)/2]
}
