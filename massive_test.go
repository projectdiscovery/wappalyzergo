package wappalyzer

import (
	"strings"
	"sync"
	"testing"
)

// TestMassiveMatchAgreement compares the prefilter with an unfiltered client
// on a body for every HTML pattern and every script URL pattern.
func TestMassiveMatchAgreement(t *testing.T) {
	fast, err := New()
	if err != nil {
		t.Fatal(err)
	}
	slow, err := New()
	if err != nil {
		t.Fatal(err)
	}
	stripPrefilter(slow)

	targets := agreementTargets(fast)
	t.Logf("bodies %d", len(targets))

	headers := map[string][]string{"Content-Type": {"text/html; charset=utf-8"}}
	jobs := make(chan []byte, 32)
	var wg sync.WaitGroup
	var mu sync.Mutex
	mismatches := 0
	const workers = 8
	const maxReport = 8
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for body := range jobs {
				got := fast.Fingerprint(headers, body)
				want := slow.Fingerprint(headers, body)
				if sameApps(got, want) {
					continue
				}
				mu.Lock()
				mismatches++
				if mismatches <= maxReport {
					t.Errorf("body %q\n only prefilter %v\n only regex %v",
						snippet(body), onlyApps(got, want), onlyApps(want, got))
				}
				mu.Unlock()
			}
		}()
	}
	for _, body := range targets {
		jobs <- body
	}
	close(jobs)
	wg.Wait()
	if mismatches > 0 {
		t.Fatalf("%d bodies disagreed", mismatches)
	}
}

func agreementTargets(w *Wappalyze) [][]byte {
	seen := make(map[string]struct{})
	var targets [][]byte
	add := func(body string) {
		if _, ok := seen[body]; ok {
			return
		}
		seen[body] = struct{}{}
		targets = append(targets, []byte(body))
	}
	add("")
	add(strings.Repeat("z", 2048))

	for _, fingerprint := range w.fingerprints.Apps {
		for _, pattern := range fingerprint.html {
			for _, group := range pattern.literals {
				text := strings.Join(group, " ")
				add(htmlBody(text))
				add(htmlBody(strings.ToUpper(text)))
				add(htmlBody(strings.Repeat("z", 800) + text + strings.Repeat("q", 800)))
			}
		}
		for _, pattern := range fingerprint.scriptSrc {
			for _, group := range pattern.literals {
				text := strings.Join(group, "/")
				add(scriptBody(text))
				add(scriptBody(strings.ToUpper(text)))
			}
		}
	}
	return targets
}

func htmlBody(text string) string {
	return "<!doctype html><html><body>" + text + "</body></html>"
}

func scriptBody(src string) string {
	return `<!doctype html><html><head><script src="` + src + `"></script></head><body></body></html>`
}

func snippet(body []byte) string {
	text := string(body)
	if len(text) > 180 {
		text = text[:180] + "..."
	}
	return text
}

func onlyApps(got, want map[string]struct{}) []string {
	var names []string
	for name := range got {
		if _, ok := want[name]; !ok {
			names = append(names, name)
		}
	}
	return names
}
