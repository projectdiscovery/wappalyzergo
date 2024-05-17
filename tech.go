package wappalyzer

import (
	"bytes"
	"encoding/json"
	"strings"
)

// Wappalyze is a client for working with tech detection
type Wappalyze struct {
	original     *Fingerprints
	fingerprints *CompiledFingerprints
}

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

// GetFingerprints returns the original fingerprints
func (s *Wappalyze) GetFingerprints() *Fingerprints {
	return s.original
}

// GetCompiledFingerprints returns the compiled fingerprints
func (s *Wappalyze) GetCompiledFingerprints() *CompiledFingerprints {
	return s.fingerprints
}

// loadFingerprints loads the fingerprints and compiles them
func (s *Wappalyze) loadFingerprints() error {
	var fingerprintsStruct Fingerprints
	err := json.Unmarshal([]byte(fingerprints), &fingerprintsStruct)
	if err != nil {
		return err
	}

	s.original = &fingerprintsStruct
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
func (s *Wappalyze) Fingerprint(headers map[string][]string, body []byte) map[string]struct{} {
	uniqueFingerprints := NewUniqueFingerprints()

	// Lowercase everything that we have received to check
	normalizedBody := bytes.ToLower(body)
	normalizedHeaders := s.normalizeHeaders(headers)

	// Run header based fingerprinting if the number
	// of header checks if more than 0.
	for _, application := range s.checkHeaders(normalizedHeaders) {
		uniqueFingerprints.SetIfNotExists(application)
	}

	cookies := s.findSetCookie(normalizedHeaders)
	// Run cookie based fingerprinting if we have a set-cookie header
	if len(cookies) > 0 {
		for _, application := range s.checkCookies(cookies) {
			uniqueFingerprints.SetIfNotExists(application)
		}
	}

	// Check for stuff in the body finally
	bodyTech := s.checkBody(normalizedBody)
	for _, application := range bodyTech {
		uniqueFingerprints.SetIfNotExists(application)
	}
	return uniqueFingerprints.GetValues()
}

type UniqueFingerprints struct {
	values map[string]struct{}
}

func NewUniqueFingerprints() UniqueFingerprints {
	return UniqueFingerprints{
		values: make(map[string]struct{}),
	}
}

func (u UniqueFingerprints) GetValues() map[string]struct{} {
	return u.values
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

func (u UniqueFingerprints) SetIfNotExists(value string) {
	app, version := separateAppVersion(value)
	if _, ok := u.values[app]; ok {
		// Handles case when we get additional version information next
		if version != "" {
			delete(u.values, app)
			u.values[strings.Join([]string{app, version}, versionSeparator)] = struct{}{}
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
	u.values[value] = struct{}{}
}

// FingerprintWithTitle identifies technologies on a target,
// based on the received response headers and body.
// It also returns the title of the page.
//
// Body should not be mutated while this function is being called, or it may
// lead to unexpected things.
func (s *Wappalyze) FingerprintWithTitle(headers map[string][]string, body []byte) (map[string]struct{}, string) {
	uniqueFingerprints := NewUniqueFingerprints()

	// Lowercase everything that we have received to check
	normalizedBody := bytes.ToLower(body)
	normalizedHeaders := s.normalizeHeaders(headers)

	// Run header based fingerprinting if the number
	// of header checks if more than 0.
	for _, application := range s.checkHeaders(normalizedHeaders) {
		uniqueFingerprints.SetIfNotExists(application)
	}

	cookies := s.findSetCookie(normalizedHeaders)
	// Run cookie based fingerprinting if we have a set-cookie header
	if len(cookies) > 0 {
		for _, application := range s.checkCookies(cookies) {
			uniqueFingerprints.SetIfNotExists(application)
		}
	}

	// Check for stuff in the body finally
	if strings.Contains(normalizedHeaders["content-type"], "text/html") {
		bodyTech := s.checkBody(normalizedBody)
		for _, application := range bodyTech {
			uniqueFingerprints.SetIfNotExists(application)
		}
		title := s.getTitle(body)
		return uniqueFingerprints.GetValues(), title
	}
	return uniqueFingerprints.GetValues(), ""
}

// FingerprintWithInfo identifies technologies on a target,
// based on the received response headers and body.
// It also returns basic information about the technology, such as description
// and website URL as well as icon.
//
// Body should not be mutated while this function is being called, or it may
// lead to unexpected things.
func (s *Wappalyze) FingerprintWithInfo(headers map[string][]string, body []byte) map[string]AppInfo {
	apps := s.Fingerprint(headers, body)
	result := make(map[string]AppInfo, len(apps))

	for app := range apps {
		if fingerprint, ok := s.fingerprints.Apps[app]; ok {
			result[app] = AppInfoFromFingerprint(fingerprint)
		}

		// Handle colon separated values
		if strings.Contains(app, versionSeparator) {
			if parts := strings.Split(app, versionSeparator); len(parts) == 2 {
				if fingerprint, ok := s.fingerprints.Apps[parts[0]]; ok {
					result[app] = AppInfoFromFingerprint(fingerprint)
				}
			}
		}
	}

	return result
}

func AppInfoFromFingerprint(fingerprint *CompiledFingerprint) AppInfo {
	categories := make([]string, 0, len(fingerprint.cats))
	for _, cat := range fingerprint.cats {
		if category, ok := categoriesMapping[cat]; ok {
			categories = append(categories, category.Name)
		}
	}
	return AppInfo{
		Description: fingerprint.description,
		Website:     fingerprint.website,
		Icon:        fingerprint.icon,
		CPE:         fingerprint.cpe,
		Categories:  categories,
	}
}

// FingerprintWithCats identifies technologies on a target,
// based on the received response headers and body.
// It also returns categories information about the technology, is there's any
// Body should not be mutated while this function is being called, or it may
// lead to unexpected things.
func (s *Wappalyze) FingerprintWithCats(headers map[string][]string, body []byte) map[string]CatsInfo {
	apps := s.Fingerprint(headers, body)
	result := make(map[string]CatsInfo, len(apps))

	for app := range apps {
		if fingerprint, ok := s.fingerprints.Apps[app]; ok {
			result[app] = CatsInfo{
				Cats: fingerprint.cats,
			}
		}
	}

	return result
}
