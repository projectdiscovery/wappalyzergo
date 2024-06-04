package wappalyzer

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"strings"
)

// Wappalyze is a client for working with tech detection
type Wappalyze struct {
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

// loadFingerprints loads the fingerprints and compiles them
// func (s *Wappalyze) loadFingerprints() error {
// 	var fingerprintsStruct Fingerprints
// 	err := json.Unmarshal([]byte(fingerprints), &fingerprintsStruct)
// 	if err != nil {
// 		return err
// 	}

//		for i, fingerprint := range fingerprintsStruct.Apps {
//			s.fingerprints.Apps[i] = compileFingerprint(fingerprint)
//		}
//		return nil
//	}

// loadFingerprints loads the fingerprints and compiles them
func (s *Wappalyze) loadFingerprints() error {
	filePath := os.Getenv("FINGERPRINTS_PATH")
	var fingerprintsData []byte
	var err error

	if filePath != "" {
		fingerprintsData, err = os.ReadFile(filePath)
		if err != nil {
			log.Printf("Warning: Could not read fingerprints file from %s: %v. Using default fingerprints.", filePath, err)
			fingerprintsData = []byte(fingerprints)
		} else {
			log.Printf("Info: Loaded fingerprints from %s", filePath)
		}
	} else {
		log.Println("Warning: FINGERPRINTS_PATH environment variable not set. Using default fingerprints.")
		fingerprintsData = []byte(fingerprints)
	}

	var fingerprintsStruct Fingerprints
	err = json.Unmarshal(fingerprintsData, &fingerprintsStruct)
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
func (s *Wappalyze) Fingerprint(headers map[string][]string, body []byte) map[string]struct{} {
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
	bodyTech := s.checkBody(normalizedBody)
	for _, application := range bodyTech {
		uniqueFingerprints.setIfNotExists(application)
	}
	return uniqueFingerprints.getValues()
}

type uniqueFingerprints struct {
	values map[string]struct{}
}

func newUniqueFingerprints() uniqueFingerprints {
	return uniqueFingerprints{
		values: make(map[string]struct{}),
	}
}

func (u uniqueFingerprints) getValues() map[string]struct{} {
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

func (u uniqueFingerprints) setIfNotExists(value string) {
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
		bodyTech := s.checkBody(normalizedBody)
		for _, application := range bodyTech {
			uniqueFingerprints.setIfNotExists(application)
		}
		title := s.getTitle(body)
		return uniqueFingerprints.getValues(), title
	}
	return uniqueFingerprints.getValues(), ""
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
			result[app] = appInfoFromFingerprint(fingerprint)
		}

		// Handle colon separated values
		if strings.Contains(app, versionSeparator) {
			if parts := strings.Split(app, versionSeparator); len(parts) == 2 {
				if fingerprint, ok := s.fingerprints.Apps[parts[0]]; ok {
					result[app] = appInfoFromFingerprint(fingerprint)
				}
			}
		}
	}

	return result
}

func appInfoFromFingerprint(fingerprint *CompiledFingerprint) AppInfo {
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
