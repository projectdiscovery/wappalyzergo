package headless

import (
	"context"
	"errors"
	"strings"
	"testing"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"github.com/stretchr/testify/require"
)

type fakeBrowserPage struct {
	evaluateCalls int
	script        string
	argument      interface{}
	result        browserEvidence
	resources     map[string][]byte
	resourceErr   map[string]error
}

func (p *fakeBrowserPage) Evaluate(_ context.Context, script string, argument interface{}, result interface{}) error {
	p.evaluateCalls++
	p.script = script
	p.argument = argument
	*result.(*browserEvidence) = p.result
	return nil
}

func (p *fakeBrowserPage) GetResource(_ context.Context, url string) ([]byte, error) {
	if err := p.resourceErr[url]; err != nil {
		return nil, err
	}
	return p.resources[url], nil
}

func TestCollectorUsesOneDataOnlyEvaluation(t *testing.T) {
	maliciousRule := `safe); window.fingerprintRuleExecuted = true; //`
	page := &fakeBrowserPage{
		result: browserEvidence{
			JavaScriptProperties: map[string]string{"runtime.version": "1.2.3"},
			DOM: map[string]wappalyzer.RuntimeDOMEvidence{
				"#runtime": {Exists: true, Text: []string{"rendered"}},
			},
			Scripts:    []string{"inline marker"},
			ScriptURLs: []string{"https://example.test/runtime.js", "https://example.test/missing.js"},
		},
		resources: map[string][]byte{
			"https://example.test/runtime.js": []byte("external marker"),
		},
		resourceErr: map[string]error{
			"https://example.test/missing.js": errors.New("not cached"),
		},
	}
	collector := &Collector{page: page}
	rules := wappalyzer.RuntimeRules{
		JavaScriptProperties: []string{"runtime.version", maliciousRule},
		DOM:                  []wappalyzer.RuntimeDOMRule{{Selector: "#runtime", Exists: true, Text: true}},
		Scripts:              true,
	}

	evidence, err := collector.Collect(context.Background(), rules)
	require.NoError(t, err)
	require.Equal(t, 1, page.evaluateCalls)
	require.Equal(t, collectRuntimeEvidenceScript, page.script)
	require.NotContains(t, page.script, maliciousRule)
	require.Equal(t, rules, page.argument)
	require.Equal(t, []string{"inline marker", "external marker"}, evidence.Scripts)
	require.Equal(t, "1.2.3", evidence.JavaScriptProperties["runtime.version"])
}

func TestCollectorBoundsExternalScriptCollection(t *testing.T) {
	urls := make([]string, 0, maxExternalScripts+1)
	resources := make(map[string][]byte, maxExternalScripts+1)
	for i := 0; i < maxExternalScripts+1; i++ {
		url := strings.Repeat("u", i+1)
		urls = append(urls, url)
		resources[url] = []byte(strings.Repeat("x", maxScriptLength+1))
	}
	page := &fakeBrowserPage{
		result:    browserEvidence{ScriptURLs: urls},
		resources: resources,
	}

	evidence, err := (&Collector{page: page}).Collect(
		context.Background(), wappalyzer.RuntimeRules{Scripts: true},
	)
	require.NoError(t, err)
	require.Len(t, evidence.Scripts, maxExternalScripts)
	for _, script := range evidence.Scripts {
		require.Len(t, script, maxScriptLength)
	}
}

func TestCollectorRejectsNilPage(t *testing.T) {
	_, err := New(nil).Collect(context.Background(), wappalyzer.RuntimeRules{})
	require.EqualError(t, err, "collect runtime evidence: page is nil")
}
