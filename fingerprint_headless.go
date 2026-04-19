package wappalyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// HeadlessOptions provides configuration for the headless fingerprinting engine
type HeadlessOptions struct {
	Timeout time.Duration
}

// DefaultHeadlessOptions returns standard options for headless evaluation
func DefaultHeadlessOptions() *HeadlessOptions {
	return &HeadlessOptions{
		Timeout: 15 * time.Second, // Wait at most 15 seconds
	}
}

// FingerprintURL checks the provided URL using headless browser (chromedp) for deep JS & DOM fingerprinting
func (s *Wappalyze) FingerprintURL(ctx context.Context, url string) (map[string]struct{}, error) {
	headers, body, jsGlobals, domMatches, err := s.headlessFetch(ctx, url)
	if err != nil {
		return nil, err
	}

	uniqueFingerprints := NewUniqueFingerprints()

	// 1. Check HTTP Headers (from intercepted network traffic)
	normalizedHeaders := s.normalizeHeaders(headers)
	for _, app := range s.checkHeaders(normalizedHeaders) {
		uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
	}

	// 2. Check Set-Cookie headers
	cookies := s.findSetCookie(normalizedHeaders)
	if len(cookies) > 0 {
		for _, app := range s.checkCookies(cookies) {
			uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
		}
	}

	// 3. Check Rendered HTML Body
	normalizedBody := []byte(strings.ToLower(body))
	for _, app := range s.checkBody(normalizedBody) {
		uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
	}

	// 4. Check Extracted JS Globals
	for _, app := range s.fingerprints.matchJSGlobals(jsGlobals) {
		uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
	}

	// 5. Check Extracted DOM Elements
	for _, app := range s.fingerprints.matchDOMSelectors(domMatches) {
		uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
	}

	return uniqueFingerprints.GetValues(), nil
}

// FingerprintURLWithInfo identifies technologies and returns AppInfo
func (s *Wappalyze) FingerprintURLWithInfo(ctx context.Context, url string) (map[string]AppInfo, error) {
	apps, err := s.FingerprintURL(ctx, url)
	if err != nil {
		return nil, err
	}
	return s.EnrichWithInfo(apps), nil
}

// FingerprintURLWithCats identifies technologies and returns CatsInfo
func (s *Wappalyze) FingerprintURLWithCats(ctx context.Context, url string) (map[string]CatsInfo, error) {
	apps, err := s.FingerprintURL(ctx, url)
	if err != nil {
		return nil, err
	}
	return s.EnrichWithCats(apps), nil
}

// headlessFetch connects to a browser, loads the page, and executes scripts to pull globals and DOM attributes
func (s *Wappalyze) headlessFetch(ctx context.Context, url string) (
	headers map[string][]string,
	body string,
	jsGlobals map[string]string,
	domMatches map[string]map[string]string,
	err error,
) {
	headers = make(map[string][]string)
	jsGlobals = make(map[string]string)
	domMatches = make(map[string]map[string]string)

	c, cancel := chromedp.NewContext(ctx)
	defer cancel()

	// Capture response headers
	var requestErr error
	chromedp.ListenTarget(c, func(ev interface{}) {
		if ev, ok := ev.(*network.EventResponseReceived); ok {
			if ev.Type == network.ResourceTypeDocument || ev.Response.URL == url {
				for k, v := range ev.Response.Headers {
					if val, ok := v.(string); ok {
						headers[k] = []string{val}
					}
				}
			}
		}
	})

	// Collect all unique JS globals to evaluate
	var jsToEvaluate []string
	for _, fingerprint := range s.fingerprints.Apps {
		for jsProp := range fingerprint.js {
			jsToEvaluate = append(jsToEvaluate, jsProp)
		}
	}

	// Prepare JS code to extract globals safely
	jsPayload := `(() => {
		const result = {};
		const extract = (path) => {
			try {
				let obj = window;
				for (let part of path.split('.')) {
					if (!obj || typeof obj !== 'object') return undefined;
					obj = obj[part];
				}
				if (typeof obj === 'string' || typeof obj === 'number' || typeof obj === 'boolean') {
					return String(obj);
				}
				return typeof obj !== 'undefined' ? "true" : undefined;
			} catch (e) {
				return undefined;
			}
		};
		const props = ` + toJSON(jsToEvaluate) + `;
		for (let prop of props) {
			let val = extract(prop);
			if (val !== undefined) result[prop] = val;
		}
		return JSON.stringify(result);
	})()`

	// Collect DOM rules to query
	// fingerprint.dom is structured as map[selector]map[attribute]*ParsedPattern
	// We want to pass selectors and their mapped attributes
	type domPayloadItem struct {
		Selector   string   `json:"s"`
		Attributes []string `json:"a"`
	}

	var domToEvaluate []domPayloadItem
	for _, fingerprint := range s.fingerprints.Apps {
		for selector, attrMap := range fingerprint.dom {
			item := domPayloadItem{Selector: selector, Attributes: []string{}}
			for attr := range attrMap {
				item.Attributes = append(item.Attributes, attr)
			}
			domToEvaluate = append(domToEvaluate, item)
		}
	}

	domPayload := `(() => {
		const result = {};
		const rules = ` + toJSON(domToEvaluate) + `;
		for (let rule of rules) {
			try {
				const els = document.querySelectorAll(rule.s);
				if (els.length === 0) continue;
				result[rule.s] = {};
				
				// We check the first matched element
				const el = els[0];
				
				for (let attr of rule.a) {
					if (attr === "text") {
						result[rule.s]["text"] = el.textContent || "";
					} else if (attr === "exists" || attr === "main") {
						result[rule.s]["exists"] = "true";
					} else {
						if (el.hasAttribute(attr)) {
							result[rule.s][attr] = el.getAttribute(attr) || "";
						}
					}
				}
			} catch (e) {
				// Invalid selector or DOM exception
			}
		}
		return JSON.stringify(result);
	})()`

	var globalsJSON string
	var domJSON string

	err = chromedp.Run(c,
		network.Enable(),
		chromedp.Navigate(url),
		// Wait for body to be present, and also for a little bit to let frameworks hydrate
		chromedp.WaitReady("body"),
		chromedp.Sleep(500*time.Millisecond),
		
		chromedp.OuterHTML("html", &body),
		chromedp.Evaluate(jsPayload, &globalsJSON),
		chromedp.Evaluate(domPayload, &domJSON),
	)

	if err != nil {
		if requestErr != nil {
			return nil, "", nil, nil, fmt.Errorf("loading %s: %v", url, requestErr)
		}
		return nil, "", nil, nil, err
	}

	// Parse evaluation results
	if globalsJSON != "" {
		_ = json.Unmarshal([]byte(globalsJSON), &jsGlobals)
	}
	if domJSON != "" {
		_ = json.Unmarshal([]byte(domJSON), &domMatches)
	}

	return headers, body, jsGlobals, domMatches, nil
}

func toJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}
