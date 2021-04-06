package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"

	jsoniter "github.com/json-iterator/go"
)

var (
	fingerprints = flag.String("fingerprints", "../../fingerprints_data.go", "File to write wappalyzer fingerprints to")
)

const fingerprintURL = "https://raw.githubusercontent.com/AliasIO/wappalyzer/master/src/technologies.json"

// Fingerprints contains a map of fingerprints for tech detection
type Fingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]Fingerprint `json:"technologies"`
}

// Fingerprint is a single piece of information about a tech
type Fingerprint struct {
	Cookies map[string]string `json:"cookies"`
	JS      map[string]string `json:"js"`
	Headers map[string]string `json:"headers"`
	HTML    interface{}       `json:"html"`
	Script  interface{}       `json:"script"`
	Meta    map[string]string `json:"meta"`
	Implies interface{}       `json:"implies"`
}

// OutputFingerprints contains a map of fingerprints for tech detection
// optimized and validated for the tech detection package
type OutputFingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]OutputFingerprint `json:"apps"`
}

// OutputFingerprint is a single piece of information about a tech validated and normalized
type OutputFingerprint struct {
	Cookies map[string]string `json:"cookies"`
	JS      []string          `json:"js"`
	Headers map[string]string `json:"headers"`
	HTML    []string          `json:"html"`
	Script  []string          `json:"script"`
	Meta    map[string]string `json:"meta"`
	Implies []string          `json:"implies"`
}

func main() {
	flag.Parse()

	resp, err := http.Get(fingerprintURL)
	if err != nil {
		log.Fatalf("Could not download fingerprints: %s\n", err)
	}

	fingerprintsOld := &Fingerprints{}
	err = jsoniter.NewDecoder(resp.Body).Decode(fingerprintsOld)
	if err != nil {
		log.Fatalf("Could not read fingerprints: %s\n", err)
	}
	resp.Body.Close()

	log.Printf("Read fingerprints from the server\n")
	log.Printf("Starting normalizing of %d fingerprints...\n", len(fingerprintsOld.Apps))

	outputFingerprints := normalizeFingerprints(fingerprintsOld)

	log.Printf("Got %d valid fingerprints\n", len(outputFingerprints.Apps))

	fingerprintsFile, err := os.OpenFile(*fingerprints, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		log.Fatalf("Could not open fingerprints file %s: %s\n", *fingerprints, err)
	}

	data, err := jsoniter.Marshal(outputFingerprints)
	if err != nil {
		log.Fatalf("Could not marshal fingerprints: %s\n", err)
	}
	fingerprintsFile.WriteString(fmt.Sprintf("package wappalyze\n\nvar fingerprints = `%s`", string(data)))
	fingerprintsFile.Close()
}

func normalizeFingerprints(fingerprints *Fingerprints) *OutputFingerprints {
	outputFingerprints := &OutputFingerprints{Apps: make(map[string]OutputFingerprint)}

	for app, fingerprint := range fingerprints.Apps {
		output := OutputFingerprint{
			Cookies: make(map[string]string),
			Headers: make(map[string]string),
			Meta:    make(map[string]string),
		}
		valid := false

		for cookie, value := range fingerprint.Cookies {
			if value == "" {
				valid = true
				output.Cookies[strings.ToLower(cookie)] = value
				break
			}
			value = sanitizeValue(value)

			_, err := regexp.Compile(value)
			if err == nil {
				valid = true
				output.Cookies[strings.ToLower(cookie)] = strings.ToLower(value)
			}
		}

		for js := range fingerprint.JS {
			js = sanitizeValue(js)

			_, err := regexp.Compile(js)
			if err == nil {
				valid = true
				output.JS = append(output.JS, strings.ToLower(js))
			}
		}

		for header, pattern := range fingerprint.Headers {
			if pattern == "" {
				valid = true
				output.Headers[strings.ToLower(header)] = pattern
				break
			}
			pattern = sanitizeValue(pattern)

			_, err := regexp.Compile(pattern)
			if err == nil {
				valid = true
				output.Headers[strings.ToLower(header)] = strings.ToLower(pattern)
			}
		}

		// Use a reflect type swtich for determining html tag type
		if fingerprint.HTML != nil {
			v := reflect.ValueOf(fingerprint.HTML)
			switch v.Kind() {
			case reflect.String:
				data := v.Interface().(string)
				data = sanitizeValue(data)

				_, err := regexp.Compile(data)
				if err == nil {
					valid = true
					output.HTML = append(output.HTML, strings.ToLower(data))
				}
			case reflect.Slice:
				data := v.Interface().([]interface{})

				for _, pattern := range data {
					pat := pattern.(string)
					pat = sanitizeValue(pat)

					_, err := regexp.Compile(pat)
					if err == nil {
						valid = true
						output.HTML = append(output.HTML, strings.ToLower(pat))
					}
				}
			}
		}

		// Use a reflect type swtich for determining script tag type
		if fingerprint.Script != nil {
			v := reflect.ValueOf(fingerprint.Script)
			switch v.Kind() {
			case reflect.String:
				data := v.Interface().(string)
				data = sanitizeValue(data)

				_, err := regexp.Compile(data)
				if err == nil {
					valid = true
					output.Script = append(output.Script, strings.ToLower(data))
				}
			case reflect.Slice:
				data := v.Interface().([]interface{})

				for _, pattern := range data {
					pat := pattern.(string)
					pat = sanitizeValue(pat)

					_, err := regexp.Compile(pat)
					if err == nil {
						valid = true
						output.Script = append(output.Script, strings.ToLower(pat))
					}
				}
			}
		}

		for header, pattern := range fingerprint.Meta {
			if pattern == "" {
				valid = true
				output.Meta[strings.ToLower(header)] = pattern
				break
			}

			pattern = sanitizeValue(pattern)

			_, err := regexp.Compile(pattern)
			if err == nil {
				valid = true
				output.Meta[strings.ToLower(header)] = strings.ToLower(pattern)
			}
		}

		// Use a reflect type swtich for determining implies tag type
		if fingerprint.Implies != nil {
			v := reflect.ValueOf(fingerprint.Implies)
			switch v.Kind() {
			case reflect.String:
				data := v.Interface().(string)
				output.Implies = append(output.Implies, sanitizeValue(data))
			case reflect.Slice:
				data := v.Interface().([]interface{})

				for _, pattern := range data {
					pat := pattern.(string)
					output.Implies = append(output.Implies, sanitizeValue(pat))
				}
			}
		}

		// Only add if the fingerprint is valid
		if valid {
			outputFingerprints.Apps[app] = output
		}
	}

	return outputFingerprints
}

// sanitizeValue sanitizes the value and removes version info setc
func sanitizeValue(value string) string {
	index := strings.Index(value, "\\;")
	if index == -1 {
		return value
	}
	return value[:index]
}
