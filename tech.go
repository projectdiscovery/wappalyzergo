package wappalyzer

import (
	"bytes"
	"encoding/json"
	"strings"
)

type (
	// Wappalyze is a client for working with tech detection
	Wappalyze struct {
		fingerprints *CompiledFingerprints
	}

	Technology struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Info    any    `json:"info"`
	}
)

// New creates a new tech detection instance
func New() (*Wappalyze, error) {
	wappalyze := &Wappalyze{
		fingerprints: &CompiledFingerprints{
			Apps: make(map[string]*CompiledFingerprint),
		},
	}

	err := wappalyze.loadFingerprints()
	if err != nil {
		return nil, err
	}
	return wappalyze, nil
}

// loadFingerprints loads the fingerprints and compiles them
func (s *Wappalyze) loadFingerprints() error {
	var fingerprintsStruct Fingerprints
	err := json.Unmarshal([]byte(fingerprints), &fingerprintsStruct)
	if err != nil {
		return err
	}

	for i, fingerprint := range fingerprintsStruct.Apps {
		s.fingerprints.Apps[i] = compileFingerprint(fingerprint)
	}
	return nil
}

// Fingerprint identifies technologies on a target,
// based on the received response headers and body.
//
// Body should not be mutated while this function is being called, or it may
// lead to unexpected things.
func (s *Wappalyze) Fingerprint(url string, headers map[string][]string, body []byte) []Technology {
	uniqueFingerprints := newUniqueFingerprints()

	// Lowercase everything that we have received to check
	normalizedBody := bytes.ToLower(body)
	normalizedHeaders := s.normalizeHeaders(headers)

	// Run header based fingerprinting if the number
	// of header checks if more than 0.
	for _, application := range s.checkHeaders(normalizedHeaders) {
		uniqueFingerprints.setIfNotExists(application)
	}

	cookies := s.findSetCookie(normalizedHeaders)
	// Run cookie based fingerprinting if we have a set-cookie header
	if len(cookies) > 0 {
		for _, application := range s.checkCookies(cookies) {
			uniqueFingerprints.setIfNotExists(application)
		}
	}

	// Check for stuff in the body finally
	bodyTech := s.checkBody(url, normalizedBody)
	for _, application := range bodyTech {
		uniqueFingerprints.setIfNotExists(application)
	}
	return uniqueFingerprints.getTechnologies()
}

type uniqueFingerprints struct {
	values map[string]any
}

func newUniqueFingerprints() uniqueFingerprints {
	return uniqueFingerprints{
		values: make(map[string]any),
	}
}

func (u uniqueFingerprints) getValues() map[string]any {
	return u.values
}

func (u uniqueFingerprints) getTechnologies() []Technology {
	var technologies []Technology
	for key, value := range u.values {
		technology := strings.Split(key, ":")
		name := technology[0]
		version := ""
		if len(technology) > 1 {
			version = technology[1]
		}

		technologies = append(technologies, Technology{
			Name:    name,
			Version: version,
			Info:    value,
		})
	}
	return technologies
}

const versionSeparator = ":"

// separateAppVersion returns app name and version
func separateAppVersion(value string) (string, string) {
	if strings.Contains(value, versionSeparator) {
		if parts := strings.Split(value, versionSeparator); len(parts) == 2 {
			return parts[0], parts[1]
		}
	}
	return value, ""
}

func (u uniqueFingerprints) setIfNotExists(value string) {
	app, version := separateAppVersion(value)
	if _, ok := u.values[app]; ok {
		// Handles case when we get additional version information next
		if version != "" {
			delete(u.values, app)
			u.values[strings.Join([]string{app, version}, versionSeparator)] = interface{}(nil)
		}
		return
	}

	// Handle duplication for : based values
	for k := range u.values {
		if strings.Contains(k, versionSeparator) {
			if parts := strings.Split(k, versionSeparator); len(parts) == 2 && parts[0] == value {
				return
			}
		}
	}
	u.values[value] = interface{}(nil)
}

// FingerprintWithTitle identifies technologies on a target,
// based on the received response headers and body.
// It also returns the title of the page.
//
// Body should not be mutated while this function is being called, or it may
// lead to unexpected things.
func (s *Wappalyze) FingerprintWithTitle(url string, headers map[string][]string, body []byte) ([]Technology, string) {
	uniqueFingerprints := newUniqueFingerprints()

	// Lowercase everything that we have received to check
	normalizedBody := bytes.ToLower(body)
	normalizedHeaders := s.normalizeHeaders(headers)

	// Run header based fingerprinting if the number
	// of header checks if more than 0.
	for _, application := range s.checkHeaders(normalizedHeaders) {
		uniqueFingerprints.setIfNotExists(application)
	}

	cookies := s.findSetCookie(normalizedHeaders)
	// Run cookie based fingerprinting if we have a set-cookie header
	if len(cookies) > 0 {
		for _, application := range s.checkCookies(cookies) {
			uniqueFingerprints.setIfNotExists(application)
		}
	}

	// Check for stuff in the body finally
	if strings.Contains(normalizedHeaders["content-type"], "text/html") {
		bodyTech := s.checkBody(url, normalizedBody)
		for _, application := range bodyTech {
			uniqueFingerprints.setIfNotExists(application)
		}
		title := s.getTitle(body)
		return uniqueFingerprints.getTechnologies(), title
	}
	return uniqueFingerprints.getTechnologies(), ""
}

// FingerprintWithInfo identifies technologies on a target,
// based on the received response headers and body.
// It also returns basic information about the technology, such as description
// and website URL.
//
// Body should not be mutated while this function is being called, or it may
// lead to unexpected things.
func (s *Wappalyze) FingerprintWithInfo(url string, headers map[string][]string, body []byte) []Technology {
	var technologies []Technology

	apps := s.Fingerprint(url, headers, body)
	for _, app := range apps {
		if fingerprint, ok := s.fingerprints.Apps[app.Name]; ok {
			app.Info = AppInfo{
				Description: fingerprint.description,
				Website:     fingerprint.website,
				CPE:         fingerprint.cpe,
			}
			technologies = append(technologies, app)
		}
	}

	return technologies
}

// FingerprintWithCats identifies technologies on a target,
// based on the received response headers and body.
// It also returns categories information about the technology, is there's any
// Body should not be mutated while this function is being called, or it may
// lead to unexpected things.
func (s *Wappalyze) FingerprintWithCats(url string, headers map[string][]string, body []byte) []Technology {
	var technologies []Technology

	apps := s.Fingerprint(url, headers, body)
	for _, app := range apps {
		if fingerprint, ok := s.fingerprints.Apps[app.Name]; ok {
			app.Info = CatsInfo{
				Cats: fingerprint.cats,
			}
			technologies = append(technologies, app)
		}
	}

	return technologies
}
