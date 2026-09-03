package headless_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"github.com/projectdiscovery/wappalyzergo/headless"
	"github.com/stretchr/testify/require"
)

func TestCollectorWithLocalBrowser(t *testing.T) {
	chrome, err := exec.LookPath("google-chrome")
	if err != nil {
		chrome, err = exec.LookPath("chromium")
	}
	if err != nil {
		t.Skip("local Chrome or Chromium is not installed")
	}

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/runtime.js" {
			response.Header().Set("Content-Type", "application/javascript")
			_, _ = response.Write([]byte(`window.externalLoaded = true; /* external-only-marker */`))
			return
		}

		response.Header().Set("Content-Type", "text/html")
		_, _ = response.Write([]byte(`<!doctype html>
<html><body>
<div id="runtime" data-version="6.2" __proto__="safe">Rendered marker</div>
<script src="/runtime.js"></script>
<script>
window.runtime = { version: "5.4.3" };
window.fingerprintRuleExecuted = false;
document.querySelector("#runtime").runtimeProperty = "property-3.8";
const inlineMarker = "inline-only-marker";
</script>
</body></html>`))
	}))
	defer server.Close()

	client := newRuntimeClient(t)
	controlURL, err := launcher.New().Bin(chrome).Headless(true).NoSandbox(true).Launch()
	require.NoError(t, err)

	browser := rod.New().ControlURL(controlURL)
	require.NoError(t, browser.Connect())
	t.Cleanup(func() {
		require.NoError(t, browser.Close())
	})

	page, err := browser.Page(proto.TargetCreateTarget{URL: server.URL})
	require.NoError(t, err)
	require.NoError(t, page.WaitLoad())

	matches, err := client.FingerprintWithRuntime(
		context.Background(),
		nil,
		nil,
		wappalyzer.RuntimeOptions{
			Collector: headless.New(page),
			Timeout:   5 * time.Second,
		},
	)
	require.NoError(t, err)
	require.Equal(t, map[string]struct{}{
		"JavaScript Tech:5.4.3":  {},
		"Implied Tech":           {},
		"DOM Exists Tech":        {},
		"DOM Text Tech":          {},
		"DOM Attribute Tech:6.2": {},
		"DOM Property Tech:3.8":  {},
		"DOM Prototype Key Tech": {},
		"Inline Script Tech":     {},
		"External Script Tech":   {},
	}, matches)

	value, err := page.Eval(`() => window.fingerprintRuleExecuted`)
	require.NoError(t, err)
	require.False(t, value.Value.Bool(), "fingerprint data must not execute as JavaScript")
}

func newRuntimeClient(t *testing.T) *wappalyzer.Wappalyze {
	t.Helper()

	fingerprints := wappalyzer.Fingerprints{Apps: map[string]*wappalyzer.Fingerprint{
		"JavaScript Tech": {
			JS:      map[string]string{"runtime.version": `^([\d.]+)$\;version:\1`},
			Implies: []string{"Implied Tech"},
		},
		"DOM Exists Tech": {
			Dom: map[string]map[string]interface{}{"#runtime": {"exists": ""}},
		},
		"DOM Text Tech": {
			Dom: map[string]map[string]interface{}{"#runtime": {"text": "rendered marker"}},
		},
		"DOM Attribute Tech": {
			Dom: map[string]map[string]interface{}{
				"#runtime": {
					"attributes": map[string]interface{}{
						"data-version": `^([\d.]+)$\;version:\1`,
					},
				},
			},
		},
		"DOM Property Tech": {
			Dom: map[string]map[string]interface{}{
				"#runtime": {
					"properties": map[string]interface{}{
						"runtimeProperty": `^property-([\d.]+)$\;version:\1`,
					},
				},
			},
		},
		"DOM Prototype Key Tech": {
			Dom: map[string]map[string]interface{}{
				"#runtime": {
					"attributes": map[string]interface{}{"__proto__": "safe"},
				},
			},
		},
		"Inline Script Tech":   {Script: []string{"inline-only-marker"}},
		"External Script Tech": {Script: []string{"external-only-marker"}},
		"Untrusted Rule": {
			JS: map[string]string{`safe); window.fingerprintRuleExecuted = true; //`: ""},
		},
		"Implied Tech": {},
	}}

	data, err := json.Marshal(fingerprints)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "fingerprints.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))

	client, err := wappalyzer.NewFromFile(path, false, false)
	require.NoError(t, err)
	return client
}
