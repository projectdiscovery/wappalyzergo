package wappalyzer

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
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
	ScriptSrc   []string                          `json:"scriptSrcs"`
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
	cookies map[string]*VersionRegex
	// js contains fingerprints for the js file
	js map[string]*VersionRegex
	// dom contains fingerprints for the target dom
	dom map[string]map[string]*VersionRegex
	// headers contains fingerprints for target headers
	headers map[string]*VersionRegex
	// html contains fingerprints for the target HTML
	html []*VersionRegex
	// script contains fingerprints for scripts
	script []*VersionRegex
	// scriptSrc contains fingerprints for script srcs
	scriptSrc []*VersionRegex
	// meta contains fingerprints for meta tags
	meta map[string][]*VersionRegex
	// cpe contains the cpe for a fingerpritn
	cpe string
}

func (f *CompiledFingerprint) GetJSRules() map[string]*VersionRegex {
	return f.js
}

func (f *CompiledFingerprint) GetDOMRules() map[string]map[string]*VersionRegex {
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

type VersionRegex struct {
	regex     *regexp.Regexp
	skipRegex bool
	group     int
}

const (
	versionPrefix    = "version:\\"
	confidencePrefix = "confidence:"
)

// newVersionRegex creates a new version matching regex
// TODO: handles simple group cases only as of now (no ternary)
func newVersionRegex(value string) (*VersionRegex, error) {
	splitted := strings.Split(value, "\\;")
	if len(splitted) == 0 {
		return nil, nil
	}

	compiled, err := regexp.Compile(splitted[0])
	if err != nil {
		return nil, err
	}
	skipRegex := splitted[0] == ""
	regex := &VersionRegex{regex: compiled, skipRegex: skipRegex}
	if skipRegex {
		return regex, nil
	}
	for _, part := range splitted {
		if strings.HasPrefix(part, confidencePrefix) {
			confidence := strings.TrimPrefix(part, confidencePrefix)
			if parsed, err := strconv.Atoi(confidence); err == nil {
				if parsed < 10 { // Only use high confidence regex
					return nil, nil
				}
			}
		}
		if strings.HasPrefix(part, versionPrefix) {
			group := strings.TrimPrefix(part, versionPrefix)
			if parsed, err := strconv.Atoi(group); err == nil {
				regex.group = parsed
			}
		}
	}
	return regex, nil
}

// MatchString returns true if a version regex matched.
// The found version is also returned if any.
func (v *VersionRegex) MatchString(value string) (bool, string) {
	if v.skipRegex {
		return true, ""
	}
	matches := v.regex.FindAllStringSubmatch(value, -1)
	if len(matches) == 0 {
		return false, ""
	}

	var version string
	if v.group > 0 {
		for _, match := range matches {
			version = match[v.group]
		}
	}
	return true, version
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
		dom:         make(map[string]map[string]*VersionRegex),
		cookies:     make(map[string]*VersionRegex),
		js:          make(map[string]*VersionRegex),
		headers:     make(map[string]*VersionRegex),
		html:        make([]*VersionRegex, 0, len(fingerprint.HTML)),
		script:      make([]*VersionRegex, 0, len(fingerprint.Script)),
		scriptSrc:   make([]*VersionRegex, 0, len(fingerprint.ScriptSrc)),
		meta:        make(map[string][]*VersionRegex),
		cpe:         fingerprint.CPE,
	}

	for dom, patterns := range fingerprint.Dom {
		compiled.dom[dom] = make(map[string]*VersionRegex)

		for attr, value := range patterns {
			switch attr {
			case "exists", "text":
				pattern, err := newVersionRegex(value.(string))
				if err != nil {
					continue
				}
				compiled.dom[dom]["main"] = pattern
			case "attributes":
				attrMap, ok := value.(map[string]interface{})
				if !ok {
					continue
				}
				compiled.dom[dom] = make(map[string]*VersionRegex)
				for attrName, value := range attrMap {
					pattern, err := newVersionRegex(value.(string))
					if err != nil {
						continue
					}
					compiled.dom[dom][attrName] = pattern
				}
			}
		}
	}

	for header, pattern := range fingerprint.Cookies {
		fingerprint, err := newVersionRegex(pattern)
		if err != nil {
			continue
		}
		compiled.cookies[header] = fingerprint
	}

	for k, pattern := range fingerprint.JS {
		fingerprint, err := newVersionRegex(pattern)
		if err != nil {
			continue
		}
		compiled.js[k] = fingerprint
	}

	for header, pattern := range fingerprint.Headers {
		fingerprint, err := newVersionRegex(pattern)
		if err != nil {
			continue
		}
		compiled.headers[header] = fingerprint
	}

	for _, pattern := range fingerprint.HTML {
		fingerprint, err := newVersionRegex(pattern)
		if err != nil {
			continue
		}
		compiled.html = append(compiled.html, fingerprint)
	}

	for _, pattern := range fingerprint.Script {
		fingerprint, err := newVersionRegex(pattern)
		if err != nil {
			continue
		}
		compiled.script = append(compiled.script, fingerprint)
	}

	for _, pattern := range fingerprint.ScriptSrc {
		fingerprint, err := newVersionRegex(pattern)
		if err != nil {
			continue
		}
		compiled.scriptSrc = append(compiled.scriptSrc, fingerprint)
	}

	for meta, patterns := range fingerprint.Meta {
		var compiledList []*VersionRegex

		for _, pattern := range patterns {
			fingerprint, err := newVersionRegex(pattern)
			if err != nil {
				continue
			}
			compiledList = append(compiledList, fingerprint)
		}
		compiled.meta[meta] = compiledList
	}
	return compiled
}

// matchString matches a string for the fingerprints
func (f *CompiledFingerprints) matchString(data string, part part) []string {
	var matched bool
	var technologies []string

	for app, fingerprint := range f.Apps {
		var version string

		switch part {
		case jsPart:
			for _, pattern := range fingerprint.js {
				if valid, versionString := pattern.MatchString(data); valid {
					matched = true
					version = versionString
				}
			}
		case scriptPart:
			for _, pattern := range fingerprint.scriptSrc {
				if valid, versionString := pattern.MatchString(data); valid {
					matched = true
					version = versionString
				}
			}
		case htmlPart:
			for _, pattern := range fingerprint.html {
				if valid, versionString := pattern.MatchString(data); valid {
					matched = true
					version = versionString
				}
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		if version != "" {
			app = FormatAppVersion(app, version)
		}
		// Append the technologies as well as implied ones
		technologies = append(technologies, app)
		if len(fingerprint.implies) > 0 {
			technologies = append(technologies, fingerprint.implies...)
		}
		matched = false
	}
	return technologies
}

// matchKeyValue matches a key-value store map for the fingerprints
func (f *CompiledFingerprints) matchKeyValueString(key, value string, part part) []string {
	var matched bool
	var technologies []string

	for app, fingerprint := range f.Apps {
		var version string

		switch part {
		case cookiesPart:
			for data, pattern := range fingerprint.cookies {
				if data != key {
					continue
				}

				if valid, versionString := pattern.MatchString(value); valid {
					matched = true
					version = versionString
					break
				}
			}
		case headersPart:
			for data, pattern := range fingerprint.headers {
				if data != key {
					continue
				}

				if valid, versionString := pattern.MatchString(value); valid {
					matched = true
					version = versionString
					break
				}
			}
		case metaPart:
			for data, patterns := range fingerprint.meta {
				if data != key {
					continue
				}

				for _, pattern := range patterns {
					if valid, versionString := pattern.MatchString(value); valid {
						matched = true
						version = versionString
						break
					}
				}
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		// Append the technologies as well as implied ones
		if version != "" {
			app = FormatAppVersion(app, version)
		}
		technologies = append(technologies, app)
		if len(fingerprint.implies) > 0 {
			technologies = append(technologies, fingerprint.implies...)
		}
		matched = false
	}
	return technologies
}

// matchMapString matches a key-value store map for the fingerprints
func (f *CompiledFingerprints) matchMapString(keyValue map[string]string, part part) []string {
	var matched bool
	var technologies []string

	for app, fingerprint := range f.Apps {
		var version string

		switch part {
		case cookiesPart:
			for data, pattern := range fingerprint.cookies {
				value, ok := keyValue[data]
				if !ok {
					continue
				}
				if pattern == nil {
					matched = true
				}
				if valid, versionString := pattern.MatchString(value); valid {
					matched = true
					version = versionString
					break
				}
			}
		case headersPart:
			for data, pattern := range fingerprint.headers {
				value, ok := keyValue[data]
				if !ok {
					continue
				}

				if valid, versionString := pattern.MatchString(value); valid {
					matched = true
					version = versionString
					break
				}
			}
		case metaPart:
			for data, patterns := range fingerprint.meta {
				value, ok := keyValue[data]
				if !ok {
					continue
				}

				for _, pattern := range patterns {
					if valid, versionString := pattern.MatchString(value); valid {
						matched = true
						version = versionString
						break
					}
				}
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		// Append the technologies as well as implied ones
		if version != "" {
			app = FormatAppVersion(app, version)
		}
		technologies = append(technologies, app)
		if len(fingerprint.implies) > 0 {
			technologies = append(technologies, fingerprint.implies...)
		}
		matched = false
	}
	return technologies
}

func FormatAppVersion(app, version string) string {
	return fmt.Sprintf("%s:%s", app, version)
}

// GetFingerprints returns the fingerprint string from wappalyzer
func GetFingerprints() string {
	return fingerprints
}
