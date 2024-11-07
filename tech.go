package wappalyzer

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
)

// Wappalyze is a client for working with tech detection
type Wappalyze struct {
	original     *Fingerprints
	fingerprints *CompiledFingerprints
}

// New creates a new tech detection instance
func New(customFilePaths ...string) (*Wappalyze, error) {
	wappalyze := &Wappalyze{
		fingerprints: &CompiledFingerprints{
			Apps: make(map[string]*CompiledFingerprint),
		},
	}

	var customFilePath string
	if len(customFilePaths) > 0 {
		customFilePath = customFilePaths[0]
	}

	err := wappalyze.loadFingerprints(customFilePath)
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

// loadFingerprints loads the fingerprints from the embedded JSON and optionally from a custom JSON file
func (s *Wappalyze) loadFingerprints(customFilePath string) error {
	var fingerprintsStruct Fingerprints

	// Load embedded fingerprints
	err := json.Unmarshal([]byte(fingerprints), &fingerprintsStruct)
	if err != nil {
		return err
	}

	// Load custom fingerprints if a file path is provided
	if customFilePath != "" {
		customData, err := os.ReadFile(customFilePath)
		if err != nil {
			return err
		}

		var customFingerprints Fingerprints
		err = json.Unmarshal(customData, &customFingerprints)
		if err != nil {
			return err
		}

		// Merge custom fingerprints into the existing ones
		for app, fingerprint := range customFingerprints.Apps {
			fingerprintsStruct.Apps[app] = fingerprint
		}
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
	for _, app := range s.checkHeaders(normalizedHeaders) {
		uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
	}

	cookies := s.findSetCookie(normalizedHeaders)
	// Run cookie based fingerprinting if we have a set-cookie header
	if len(cookies) > 0 {
		for _, app := range s.checkCookies(cookies) {
			uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
		}
	}

	// Check for stuff in the body finally
	bodyTech := s.checkBody(normalizedBody)
	for _, app := range bodyTech {
		uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
	}
	return uniqueFingerprints.GetValues()
}

type UniqueFingerprints struct {
	values map[string]uniqueFingerprintMetadata
}

type uniqueFingerprintMetadata struct {
	confidence int
	version    string
}

func NewUniqueFingerprints() UniqueFingerprints {
	return UniqueFingerprints{
		values: make(map[string]uniqueFingerprintMetadata),
	}
}

func (u UniqueFingerprints) GetValues() map[string]struct{} {
	values := make(map[string]struct{}, len(u.values))
	for k, v := range u.values {
		if v.confidence == 0 {
			continue
		}
		values[FormatAppVersion(k, v.version)] = struct{}{}
	}
	return values
}

const versionSeparator = ":"

func (u UniqueFingerprints) SetIfNotExists(value, version string, confidence int) {
	if _, ok := u.values[value]; ok {
		new := u.values[value]
		updatedConfidence := new.confidence + confidence
		if updatedConfidence > 100 {
			updatedConfidence = 100
		}
		new.confidence = updatedConfidence
		if new.version == "" && version != "" {
			new.version = version
		}
		u.values[value] = new
		return
	}

	u.values[value] = uniqueFingerprintMetadata{
		confidence: confidence,
		version:    version,
	}
}

type matchPartResult struct {
	application string
	confidence  int
	version     string
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
	for _, app := range s.checkHeaders(normalizedHeaders) {
		uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
	}

	cookies := s.findSetCookie(normalizedHeaders)
	// Run cookie based fingerprinting if we have a set-cookie header
	if len(cookies) > 0 {
		for _, app := range s.checkCookies(cookies) {
			uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
		}
	}

	// Check for stuff in the body finally
	if strings.Contains(normalizedHeaders["content-type"], "text/html") {
		bodyTech := s.checkBody(normalizedBody)
		for _, app := range bodyTech {
			uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
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
