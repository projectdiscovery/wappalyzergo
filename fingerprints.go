package wappalyzer

import (
	"fmt"
	"sort"
)

// Fingerprints contains a map of fingerprints for tech detection
type Fingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]*Fingerprint `json:"apps"`
}

// Fingerprint is a single piece of information about a tech validated and normalized
type Fingerprint struct {
	Cats        []int                             `json:"cats"`
	CSS         []string                          `json:"css"`
	Cookies     map[string]string                 `json:"cookies"`
	Dom         map[string]map[string]interface{} `json:"dom"`
	JS          map[string]string                 `json:"js"`
	Headers     map[string]string                 `json:"headers"`
	HTML        []string                          `json:"html"`
	Script      []string                          `json:"scripts"`
	ScriptSrc   []string                          `json:"scriptSrc"`
	Meta        map[string][]string               `json:"meta"`
	Implies     []string                          `json:"implies"`
	Description string                            `json:"description"`
	Website     string                            `json:"website"`
	CPE         string                            `json:"cpe"`
	Icon        string                            `json:"icon"`
}

// CompiledFingerprints contains a map of fingerprints for tech detection
type CompiledFingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]*CompiledFingerprint
}

// MatchingField contains a name of the given field and a parsed pattern to match the field.
type MatchingField struct {
	FieldName string
	Patterns  []*ParsedPattern
}

// ByFieldName implements sort.Interface on []MatchingField.
type ByFieldName []*MatchingField

func (a ByFieldName) Len() int           { return len(a) }
func (a ByFieldName) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByFieldName) Less(i, j int) bool { return a[i].FieldName < a[j].FieldName }

// CompiledFingerprint contains the compiled fingerprints from the tech json
type CompiledFingerprint struct {
	// cats contain categories that are implicit with this tech
	cats []int
	// implies contains technologies that are implicit with this tech
	implies []string
	// description contains fingerprint description
	description string
	// website contains a URL associated with the fingerprint
	website string
	// icon contains a Icon associated with the fingerprint
	icon string
	// cookies contains fingerprints for target cookies
	cookies []*MatchingField
	// js contains fingerprints for the js file
	js map[string]*ParsedPattern
	// dom contains fingerprints for the target dom
	dom map[string]map[string]*ParsedPattern
	// headers contains fingerprints for target headers
	headers []*MatchingField
	// html contains fingerprints for the target HTML
	html []*ParsedPattern
	// script contains fingerprints for scripts
	script []*ParsedPattern
	// scriptSrc contains fingerprints for script srcs
	scriptSrc []*ParsedPattern
	// meta contains fingerprints for meta tags
	meta []*MatchingField
	// cpe contains the cpe for a fingerpritn
	cpe string
}

func (f *CompiledFingerprint) GetJSRules() map[string]*ParsedPattern {
	return f.js
}

func (f *CompiledFingerprint) GetDOMRules() map[string]map[string]*ParsedPattern {
	return f.dom
}

// AppInfo contains basic information about an App.
type AppInfo struct {
	Description string
	Website     string
	CPE         string
	Icon        string
	Categories  []string
}

// CatsInfo contains basic information about an App.
type CatsInfo struct {
	Cats []int
}

// part is the part of the fingerprint to match
type part int

// parts that can be matched
const (
	cookiesPart part = iota + 1
	jsPart
	headersPart
	htmlPart
	scriptPart
	metaPart
)

// loadPatterns loads the fingerprint patterns and compiles regexes
func compileFingerprint(fingerprint *Fingerprint) *CompiledFingerprint {
	compiled := &CompiledFingerprint{
		cats:        fingerprint.Cats,
		implies:     fingerprint.Implies,
		description: fingerprint.Description,
		website:     fingerprint.Website,
		icon:        fingerprint.Icon,
		dom:         make(map[string]map[string]*ParsedPattern),
		cookies:     make([]*MatchingField, 0),
		js:          make(map[string]*ParsedPattern),
		headers:     make([]*MatchingField, 0),
		html:        make([]*ParsedPattern, 0, len(fingerprint.HTML)),
		script:      make([]*ParsedPattern, 0, len(fingerprint.Script)),
		scriptSrc:   make([]*ParsedPattern, 0, len(fingerprint.ScriptSrc)),
		meta:        make([]*MatchingField, 0),
		cpe:         fingerprint.CPE,
	}

	for dom, patterns := range fingerprint.Dom {
		compiled.dom[dom] = make(map[string]*ParsedPattern)

		for attr, value := range patterns {
			switch attr {
			case "exists", "text":
				pattern, err := ParsePattern(value.(string))
				if err != nil {
					continue
				}
				compiled.dom[dom]["main"] = pattern
			case "attributes":
				attrMap, ok := value.(map[string]interface{})
				if !ok {
					continue
				}
				compiled.dom[dom] = make(map[string]*ParsedPattern)
				for attrName, value := range attrMap {
					pattern, err := ParsePattern(value.(string))
					if err != nil {
						continue
					}
					compiled.dom[dom][attrName] = pattern
				}
			}
		}
	}

	for header, pattern := range fingerprint.Cookies {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.cookies = append(compiled.cookies, &MatchingField{
			FieldName: header,
			Patterns:  []*ParsedPattern{fingerprint},
		})
	}

	for k, pattern := range fingerprint.JS {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.js[k] = fingerprint
	}

	for header, pattern := range fingerprint.Headers {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.headers = append(compiled.headers, &MatchingField{
			FieldName: header,
			Patterns:  []*ParsedPattern{fingerprint},
		})
	}

	for _, pattern := range fingerprint.HTML {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.html = append(compiled.html, fingerprint)
	}

	for _, pattern := range fingerprint.Script {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.script = append(compiled.script, fingerprint)
	}

	for _, pattern := range fingerprint.ScriptSrc {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.scriptSrc = append(compiled.scriptSrc, fingerprint)
	}

	for meta, patterns := range fingerprint.Meta {
		var compiledList []*ParsedPattern

		for _, pattern := range patterns {
			fingerprint, err := ParsePattern(pattern)
			if err != nil {
				continue
			}
			compiledList = append(compiledList, fingerprint)
		}
		compiled.meta = append(compiled.meta, &MatchingField{
			FieldName: meta,
			Patterns:  compiledList,
		})
	}

	// Sort slices to ensure deterministic detection
	sort.Sort(ByFieldName(compiled.headers))
	sort.Sort(ByFieldName(compiled.cookies))
	sort.Sort(ByFieldName(compiled.meta))

	return compiled
}

// matchString matches a string for the fingerprints
func (f *CompiledFingerprints) matchString(data string, part part) []matchPartResult {
	var matched bool
	var technologies []matchPartResult

	for app, fingerprint := range f.Apps {
		var version string
		confidence := 100

		switch part {
		case jsPart:
			for _, pattern := range fingerprint.js {
				if valid, versionString := pattern.Evaluate(data); valid {
					matched = true
					if version == "" && versionString != "" {
						version = versionString
					}
					confidence = pattern.Confidence
				}
			}
		case scriptPart:
			for _, pattern := range fingerprint.scriptSrc {
				if valid, versionString := pattern.Evaluate(data); valid {
					matched = true
					if version == "" && versionString != "" {
						version = versionString
					}
					confidence = pattern.Confidence
				}
			}
		case htmlPart:
			for _, pattern := range fingerprint.html {
				if valid, versionString := pattern.Evaluate(data); valid {
					matched = true
					if version == "" && versionString != "" {
						version = versionString
					}
					confidence = pattern.Confidence
				}
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		// Append the technologies as well as implied ones
		technologies = append(technologies, matchPartResult{
			application: app,
			version:     version,
			confidence:  confidence,
		})
		if len(fingerprint.implies) > 0 {
			for _, implies := range fingerprint.implies {
				technologies = append(technologies, matchPartResult{
					application: implies,
					confidence:  confidence,
				})
			}
		}
		matched = false
	}
	return technologies
}

// matchKeyValue matches a key-value store map for the fingerprints
func (f *CompiledFingerprints) matchKeyValueString(key, value string, part part) []matchPartResult {
	var matched bool
	var technologies []matchPartResult

	for app, fingerprint := range f.Apps {
		var version string
		confidence := 100

		switch part {
		case cookiesPart:
			for _, field := range fingerprint.cookies {
				if field.FieldName != key {
					continue
				}
				for _, pattern := range field.Patterns {
					if valid, versionString := pattern.Evaluate(value); valid {
						matched = true
						if version == "" && versionString != "" {
							version = versionString
						}
						confidence = pattern.Confidence
						break
					}
				}
				if matched {
					break
				}
			}
		case headersPart:
			for _, field := range fingerprint.headers {
				if field.FieldName != key {
					continue
				}

				for _, pattern := range field.Patterns {
					if valid, versionString := pattern.Evaluate(value); valid {
						matched = true
						if version == "" && versionString != "" {
							version = versionString
						}
						confidence = pattern.Confidence
						break
					}
				}
				if matched {
					break
				}
			}
		case metaPart:
			for _, field := range fingerprint.meta {
				if field.FieldName != key {
					continue
				}

				for _, pattern := range field.Patterns {
					if valid, versionString := pattern.Evaluate(value); valid {
						matched = true
						if version == "" && versionString != "" {
							version = versionString
						}
						confidence = pattern.Confidence
						break
					}
				}
				if matched {
					break
				}
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		technologies = append(technologies, matchPartResult{
			application: app,
			version:     version,
			confidence:  confidence,
		})
		if len(fingerprint.implies) > 0 {
			for _, implies := range fingerprint.implies {
				technologies = append(technologies, matchPartResult{
					application: implies,
					confidence:  confidence,
				})
			}
		}
		matched = false
	}
	return technologies
}

// matchMapString matches a key-value store map for the fingerprints
func (f *CompiledFingerprints) matchMapString(keyValue map[string]string, part part) []matchPartResult {
	var matched bool
	var technologies []matchPartResult

	for app, fingerprint := range f.Apps {
		var version string
		confidence := 100

		switch part {
		case cookiesPart:
			for _, field := range fingerprint.cookies {
				value, ok := keyValue[field.FieldName]
				if !ok {
					continue
				}
				for _, pattern := range field.Patterns {
					if pattern == nil {
						matched = true
						break
					}
					if valid, versionString := pattern.Evaluate(value); valid {
						matched = true
						if version == "" && versionString != "" {
							version = versionString
						}
						confidence = pattern.Confidence
						break
					}
				}
				if matched {
					break
				}
			}
		case headersPart:
			for _, field := range fingerprint.headers {
				value, ok := keyValue[field.FieldName]
				if !ok {
					continue
				}

				for _, pattern := range field.Patterns {
					if valid, versionString := pattern.Evaluate(value); valid {
						matched = true
						if version == "" && versionString != "" {
							version = versionString
						}
						confidence = pattern.Confidence
						break
					}
				}
				if matched {
					break
				}
			}
		case metaPart:
			for _, field := range fingerprint.meta {
				value, ok := keyValue[field.FieldName]
				if !ok {
					continue
				}

				for _, pattern := range field.Patterns {
					if valid, versionString := pattern.Evaluate(value); valid {
						matched = true
						if version == "" && versionString != "" {
							version = versionString
						}
						confidence = pattern.Confidence
						break
					}
				}
				if matched {
					break
				}
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		technologies = append(technologies, matchPartResult{
			application: app,
			version:     version,
			confidence:  confidence,
		})
		if len(fingerprint.implies) > 0 {
			for _, implies := range fingerprint.implies {
				technologies = append(technologies, matchPartResult{
					application: implies,
					confidence:  confidence,
				})
			}
		}
		matched = false
	}
	return technologies
}

func FormatAppVersion(app, version string) string {
	if version == "" {
		return app
	}
	return fmt.Sprintf("%s:%s", app, version)
}

// GetFingerprints returns the fingerprint string from wappalyzer
func GetFingerprints() string {
	return fingerprints
}
