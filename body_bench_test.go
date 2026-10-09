package wappalyzer

import (
	"fmt"
	"strings"
	"testing"
)

func BenchmarkRealisticBody(b *testing.B) {
	headers := map[string][]string{"Content-Type": {"text/html; charset=utf-8"}}
	for _, size := range []int{8 << 10, 64 << 10, 256 << 10} {
		body := realisticPage(8, size)
		for _, disable := range []bool{false, true} {
			label := "prefilter"
			if disable {
				label = "regex"
			}
			w := newClient(b, disable)
			b.Run(fmt.Sprintf("%s/%dKB", label, size>>10), func(b *testing.B) {
				for b.Loop() {
					benchmarkFingerprintResult = w.Fingerprint(headers, body)
				}
			})
		}
	}
}

func newClient(b *testing.B, disablePrefilter bool) *Wappalyze {
	b.Helper()
	w, err := New()
	if err != nil {
		b.Fatal(err)
	}
	if !disablePrefilter {
		return w
	}
	stripPrefilter(w)
	return w
}

func stripPrefilter(w *Wappalyze) {
	w.fingerprints.htmlIndex = nil
	w.fingerprints.scriptIndex = nil
	for _, fingerprint := range w.fingerprints.Apps {
		clearLiterals(fingerprint.html)
		clearLiterals(fingerprint.script)
		clearLiterals(fingerprint.scriptSrc)
	}
}

func clearLiterals(patterns []*ParsedPattern) {
	for _, pattern := range patterns {
		if pattern != nil {
			pattern.literals = nil
		}
	}
}

func realisticPage(scripts, size int) []byte {
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8">`)
	for i := 0; i < scripts; i++ {
		fmt.Fprintf(&b, `<script src="/static/app-%d.js"></script>`, i)
	}
	b.WriteString(`</head><body><div id="app"><p>`)
	const sentence = "The quick brown fox jumps over the lazy dog. "
	for b.Len() < size-32 {
		b.WriteString(sentence)
	}
	b.WriteString(`</p></div></body></html>`)
	page := b.String()
	if len(page) > size {
		page = page[:size]
	}
	return []byte(page)
}
