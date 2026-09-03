package wappalyzer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type runtimeCollectorFunc func(context.Context, RuntimeRules) (RuntimeEvidence, error)

func (f runtimeCollectorFunc) Collect(ctx context.Context, rules RuntimeRules) (RuntimeEvidence, error) {
	return f(ctx, rules)
}

func TestFingerprintWithRuntime(t *testing.T) {
	wappalyzer := newRuntimeTestWappalyze(map[string]*Fingerprint{
		"Passive Tech": {
			Headers: map[string]string{"x-passive": "present"},
		},
		"JavaScript Tech": {
			JS:      map[string]string{"runtime.version": `^([\d.]+)$\;version:\1\;confidence:40`},
			Implies: []string{"Implied Tech"},
		},
		"DOM Exists Tech": {
			Dom: map[string]map[string]interface{}{
				"#runtime": {"exists": `\;confidence:20`},
			},
		},
		"DOM Text Tech": {
			Dom: map[string]map[string]interface{}{
				"#runtime": {"text": `rendered marker\;confidence:20`},
			},
		},
		"DOM Attribute Tech": {
			Dom: map[string]map[string]interface{}{
				"#runtime": {
					"attributes": map[string]interface{}{
						"data-version": `^([\d.]+)$\;version:\1\;confidence:20`,
					},
				},
			},
		},
		"DOM Property Tech": {
			Dom: map[string]map[string]interface{}{
				"#runtime": {
					"properties": map[string]interface{}{
						"runtimeProperty": `^property-([\d.]+)$\;version:\1\;confidence:20`,
					},
				},
			},
		},
		"Script Tech": {
			Script: []string{`script-marker-([\d.]+)\;version:\1\;confidence:20`},
		},
		"Untrusted Rule": {
			JS: map[string]string{`safe); window.fingerprintRuleExecuted = true; //`: ""},
		},
		"Implied Tech": {},
	})

	passiveHeaders := map[string][]string{"X-Passive": {"present"}}
	passiveBody := []byte(`<script>script-marker-7.1</script>`)
	require.Equal(t, map[string]struct{}{"Passive Tech": {}}, wappalyzer.Fingerprint(passiveHeaders, passiveBody))

	var calls int
	collector := runtimeCollectorFunc(func(_ context.Context, rules RuntimeRules) (RuntimeEvidence, error) {
		calls++
		require.Contains(t, rules.JavaScriptProperties, "runtime.version")
		require.Contains(t, rules.JavaScriptProperties, `safe); window.fingerprintRuleExecuted = true; //`)
		require.True(t, rules.Scripts)
		require.Len(t, rules.DOM, 1)
		require.Equal(t, RuntimeDOMRule{
			Selector:   "#runtime",
			Exists:     true,
			Text:       true,
			Attributes: []string{"data-version"},
			Properties: []string{"runtimeProperty"},
		}, rules.DOM[0])

		return RuntimeEvidence{
			JavaScriptProperties: map[string]string{"runtime.version": "5.4.3"},
			DOM: map[string]RuntimeDOMEvidence{
				"#runtime": {
					Exists:     true,
					Text:       []string{"rendered marker"},
					Attributes: map[string][]string{"data-version": {"6.2"}},
					Properties: map[string][]string{"runtimeProperty": {"property-3.8"}},
				},
			},
			Scripts: []string{"const value = 'script-marker-7.1'"},
		}, nil
	})

	matches, err := wappalyzer.FingerprintWithRuntime(
		context.Background(),
		passiveHeaders,
		passiveBody,
		RuntimeOptions{Collector: collector, Timeout: time.Second},
	)
	require.NoError(t, err)
	require.Equal(t, 1, calls, "runtime evidence must be collected in one batch")
	require.Equal(t, map[string]struct{}{
		"Passive Tech":           {},
		"JavaScript Tech:5.4.3":  {},
		"Implied Tech":           {},
		"DOM Exists Tech":        {},
		"DOM Text Tech":          {},
		"DOM Attribute Tech:6.2": {},
		"DOM Property Tech:3.8":  {},
		"Script Tech:7.1":        {},
	}, matches)
}

func TestCompileFingerprintPreservesAllDOMRuleTypes(t *testing.T) {
	fingerprint := compileFingerprint(&Fingerprint{
		Dom: map[string]map[string]interface{}{
			"#runtime": {
				"exists": "",
				"text":   "marker",
				"attributes": map[string]interface{}{
					"data-runtime": "attribute",
				},
				"properties": map[string]interface{}{
					"runtimeProperty": "property",
				},
			},
		},
	})

	rule := fingerprint.runtimeDOM["#runtime"]
	require.NotNil(t, rule.exists)
	require.NotNil(t, rule.text)
	require.Contains(t, rule.attributes, "data-runtime")
	require.Contains(t, rule.properties, "runtimeProperty")
}

func TestRuntimeRulesReturnsAnIsolatedDeterministicCopy(t *testing.T) {
	wappalyzer := newRuntimeTestWappalyze(map[string]*Fingerprint{
		"B": {
			JS: map[string]string{"z.path": "", "a.path": ""},
			Dom: map[string]map[string]interface{}{
				"#z": {"attributes": map[string]interface{}{"z": "", "a": ""}},
				"#a": {"properties": map[string]interface{}{"z": "", "a": ""}},
			},
		},
	})

	rules := wappalyzer.RuntimeRules()
	require.Equal(t, []string{"a.path", "z.path"}, rules.JavaScriptProperties)
	require.Equal(t, []RuntimeDOMRule{
		{Selector: "#a", Properties: []string{"a", "z"}},
		{Selector: "#z", Attributes: []string{"a", "z"}},
	}, rules.DOM)

	rules.JavaScriptProperties[0] = "changed"
	rules.DOM[0].Properties[0] = "changed"
	require.Equal(t, "a.path", wappalyzer.RuntimeRules().JavaScriptProperties[0])
	require.Equal(t, "a", wappalyzer.RuntimeRules().DOM[0].Properties[0])
}

func TestEmbeddedRuntimeRulesIncludeDOMProperties(t *testing.T) {
	wappalyzer, err := New()
	require.NoError(t, err)

	properties := make(map[string]struct{})
	for _, rule := range wappalyzer.RuntimeRules().DOM {
		for _, property := range rule.Properties {
			properties[property] = struct{}{}
		}
	}
	require.Contains(t, properties, "_reactRootContainer")
	require.Contains(t, properties, "__k")
}

func TestFingerprintWithRuntimeAppliesDefaultTimeout(t *testing.T) {
	wappalyzer := newRuntimeTestWappalyze(nil)
	collector := runtimeCollectorFunc(func(ctx context.Context, _ RuntimeRules) (RuntimeEvidence, error) {
		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		remaining := time.Until(deadline)
		require.Positive(t, remaining)
		require.LessOrEqual(t, remaining, DefaultRuntimeTimeout)
		return RuntimeEvidence{}, nil
	})

	_, err := wappalyzer.FingerprintWithRuntime(
		context.Background(), nil, nil, RuntimeOptions{Collector: collector},
	)
	require.NoError(t, err)
}

func TestFingerprintWithRuntimeHonorsTimeoutAndReturnsPassiveMatches(t *testing.T) {
	wappalyzer := newRuntimeTestWappalyze(map[string]*Fingerprint{
		"Passive Tech": {Headers: map[string]string{"x-passive": "present"}},
	})
	collector := runtimeCollectorFunc(func(ctx context.Context, _ RuntimeRules) (RuntimeEvidence, error) {
		<-ctx.Done()
		return RuntimeEvidence{}, ctx.Err()
	})

	start := time.Now()
	matches, err := wappalyzer.FingerprintWithRuntime(
		context.Background(),
		map[string][]string{"X-Passive": {"present"}},
		nil,
		RuntimeOptions{Collector: collector, Timeout: 20 * time.Millisecond},
	)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), time.Second)
	require.Equal(t, map[string]struct{}{"Passive Tech": {}}, matches)
}

func TestRuntimeEvidenceMergesConfidenceVersionAndImplication(t *testing.T) {
	wappalyzer := newRuntimeTestWappalyze(map[string]*Fingerprint{
		"Runtime Tech": {
			JS: map[string]string{"runtime.version": `^v([\d.]+)$\;version:\1\;confidence:30`},
			Dom: map[string]map[string]interface{}{
				"#runtime": {
					"attributes": map[string]interface{}{
						"data-version": `^d([\d.]+)$\;version:\1\;confidence:20`,
					},
				},
			},
			Implies: []string{"Implied Tech"},
		},
		"Implied Tech": {},
	})
	unique := NewUniqueFingerprints()

	wappalyzer.mergeRuntimeEvidence(unique, RuntimeEvidence{
		JavaScriptProperties: map[string]string{"runtime.version": "v2.0"},
		DOM: map[string]RuntimeDOMEvidence{
			"#runtime": {
				Exists:     true,
				Attributes: map[string][]string{"data-version": {"d3.4"}},
			},
		},
	})

	require.Equal(t, uniqueFingerprintMetadata{confidence: 50, version: "3.4"}, unique.values["Runtime Tech"])
	require.Equal(t, uniqueFingerprintMetadata{confidence: 50}, unique.values["Implied Tech"])
}

func TestFingerprintWithRuntimeMergesPartialEvidenceOnError(t *testing.T) {
	wappalyzer := newRuntimeTestWappalyze(map[string]*Fingerprint{
		"Runtime Tech": {JS: map[string]string{"runtime": ""}},
	})
	expectedErr := errors.New("partial collection")
	collector := runtimeCollectorFunc(func(context.Context, RuntimeRules) (RuntimeEvidence, error) {
		return RuntimeEvidence{JavaScriptProperties: map[string]string{"runtime": "true"}}, expectedErr
	})

	matches, err := wappalyzer.FingerprintWithRuntime(
		context.Background(), nil, nil, RuntimeOptions{Collector: collector, Timeout: time.Second},
	)
	require.ErrorIs(t, err, expectedErr)
	require.Equal(t, map[string]struct{}{"Runtime Tech": {}}, matches)
}

func newRuntimeTestWappalyze(apps map[string]*Fingerprint) *Wappalyze {
	original := &Fingerprints{Apps: apps}
	compiled := &CompiledFingerprints{Apps: make(map[string]*CompiledFingerprint, len(apps))}
	for name, fingerprint := range apps {
		compiled.Apps[name] = compileFingerprint(fingerprint)
	}

	return &Wappalyze{
		original:     original,
		fingerprints: compiled,
		runtimeRules: compileRuntimeRules(compiled),
	}
}
