package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
)

var fingerprints = flag.String("fingerprints", "../../fingerprints_data.json", "File to write wappalyzer fingerprints to")

// Fingerprints contains a map of fingerprints for tech detection
type Fingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]Fingerprint `json:"technologies"`
}

// Fingerprint is a single piece of information about a tech
type Fingerprint struct {
	Cats        []int                  `json:"cats"`
	CSS         interface{}            `json:"css"`
	Cookies     map[string]string      `json:"cookies"`
	JS          map[string]string      `json:"js"`
	Headers     map[string]string      `json:"headers"`
	HTML        interface{}            `json:"html"`
	Script      interface{}            `json:"scripts"`
	ScriptSrc   interface{}            `json:"scriptSrc"`
	Meta        map[string]interface{} `json:"meta"`
	Implies     interface{}            `json:"implies"`
	Description string                 `json:"description"`
	Website     string                 `json:"website"`
	CPE         string                 `json:"cpe"`
}

// OutputFingerprints contains a map of fingerprints for tech detection
// optimized and validated for the tech detection package
type OutputFingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]OutputFingerprint `json:"apps"`
}

// OutputFingerprint is a single piece of information about a tech validated and normalized
type OutputFingerprint struct {
	Cats        []int               `json:"cats,omitempty"`
	CSS         []string            `json:"css,omitempty"`
	Cookies     map[string]string   `json:"cookies,omitempty"`
	JS          []string            `json:"js,omitempty"`
	Headers     map[string]string   `json:"headers,omitempty"`
	HTML        []string            `json:"html,omitempty"`
	Script      []string            `json:"scripts,omitempty"`
	ScriptSrc   []string            `json:"scriptSrc,omitempty"`
	Meta        map[string][]string `json:"meta,omitempty"`
	Implies     []string            `json:"implies,omitempty"`
	Description string              `json:"description,omitempty"`
	Website     string              `json:"website,omitempty"`
	CPE         string              `json:"cpe,omitempty"`
}

const fingerprintURL = "https://raw.githubusercontent.com/Lissy93/wapalyzer/master/src/technologies/%s.json"

func makeFingerprintURLs() []string {
	files := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "_"}

	fingerprints := make([]string, 0, len(files))
	for _, item := range files {
		fingerprints = append(fingerprints, fmt.Sprintf(fingerprintURL, item))
	}
	return fingerprints
}

func main() {
	flag.Parse()

	fingerprintURLs := makeFingerprintURLs()

	fingerprintsOld := &Fingerprints{
		Apps: make(map[string]Fingerprint),
	}
	for _, fingerprintItem := range fingerprintURLs {
		if err := gatherFingerprintsFromURL(fingerprintItem, fingerprintsOld); err != nil {
			log.Fatalf("Could not gather fingerprints %s: %v\n", fingerprintItem, err)
		}
	}

	log.Printf("Read fingerprints from the server\n")
	log.Printf("Starting normalizing of %d fingerprints...\n", len(fingerprintsOld.Apps))

	outputFingerprints := normalizeFingerprints(fingerprintsOld)

	log.Printf("Got %d valid fingerprints\n", len(outputFingerprints.Apps))

	fingerprintsFile, err := os.OpenFile(*fingerprints, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o666)
	if err != nil {
		log.Fatalf("Could not open fingerprints file %s: %s\n", *fingerprints, err)
	}

	// sort map keys and pretty print the json to make git diffs useful

	data, err := json.MarshalIndent(outputFingerprints, "", "    ")
	if err != nil {
		log.Fatalf("Could not marshal fingerprints: %s\n", err)
	}
	_, err = fingerprintsFile.Write(data)
	if err != nil {
		log.Fatalf("Could not write fingerprints file: %s\n", err)
	}
	err = fingerprintsFile.Close()
	if err != nil {
		log.Fatalf("Could not close fingerprints file: %s\n", err)
	}
}

func gatherFingerprintsFromURL(URL string, fingerprints *Fingerprints) error {
	req, err := http.NewRequest(http.MethodGet, URL, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	fingerprintsOld := &Fingerprints{}
	err = json.NewDecoder(bytes.NewReader(data)).Decode(&fingerprintsOld.Apps)
	if err != nil {
		return err
	}

	for k, v := range fingerprintsOld.Apps {
		fingerprints.Apps[k] = v
	}
	return nil
}

func normalizeFingerprints(fingerprints *Fingerprints) *OutputFingerprints {
	outputFingerprints := &OutputFingerprints{Apps: make(map[string]OutputFingerprint)}

	for app, fingerprint := range fingerprints.Apps {
		output := OutputFingerprint{
			Cats:        fingerprint.Cats,
			Cookies:     make(map[string]string),
			Headers:     make(map[string]string),
			Meta:        make(map[string][]string),
			Description: fingerprint.Description,
			Website:     fingerprint.Website,
			CPE:         fingerprint.CPE,
		}

		for cookie, value := range fingerprint.Cookies {
			output.Cookies[strings.ToLower(cookie)] = strings.ToLower(value)
		}
		for js := range fingerprint.JS {
			output.JS = append(output.JS, strings.ToLower(js))
		}
		sort.Strings(output.JS)

		for header, pattern := range fingerprint.Headers {
			output.Headers[strings.ToLower(header)] = strings.ToLower(pattern)
		}

		// Use reflection type switch for determining HTML tag type
		if fingerprint.HTML != nil {
			v := reflect.ValueOf(fingerprint.HTML)

			switch v.Kind() {
			case reflect.String:
				data := v.Interface().(string)
				output.HTML = append(output.HTML, strings.ToLower(data))
			case reflect.Slice:
				data := v.Interface().([]interface{})

				for _, pattern := range data {
					pat := pattern.(string)
					output.HTML = append(output.HTML, strings.ToLower(pat))
				}
			}

			sort.Strings(output.HTML)
		}

		// Use reflection type switch for determining Script type
		if fingerprint.Script != nil {
			v := reflect.ValueOf(fingerprint.Script)

			switch v.Kind() {
			case reflect.String:
				data := v.Interface().(string)
				output.Script = append(output.Script, strings.ToLower(data))
			case reflect.Slice:
				data := v.Interface().([]interface{})
				for _, pattern := range data {
					pat := pattern.(string)
					output.Script = append(output.Script, strings.ToLower(pat))
				}
			}

			sort.Strings(output.Script)
		}

		// Use reflection type switch for determining ScriptSrc type
		if fingerprint.ScriptSrc != nil {
			v := reflect.ValueOf(fingerprint.ScriptSrc)

			switch v.Kind() {
			case reflect.String:
				data := v.Interface().(string)
				output.ScriptSrc = append(output.ScriptSrc, strings.ToLower(data))
			case reflect.Slice:
				data := v.Interface().([]interface{})
				for _, pattern := range data {
					pat := pattern.(string)
					output.ScriptSrc = append(output.ScriptSrc, strings.ToLower(pat))
				}
			}

			sort.Strings(output.ScriptSrc)
		}

		for header, pattern := range fingerprint.Meta {
			v := reflect.ValueOf(pattern)

			switch v.Kind() {
			case reflect.String:
				data := strings.ToLower(v.Interface().(string))
				if data == "" {
					output.Meta[strings.ToLower(header)] = []string{}
				} else {
					output.Meta[strings.ToLower(header)] = []string{data}
				}
			case reflect.Slice:
				data := v.Interface().([]interface{})

				final := []string{}
				for _, pattern := range data {
					pat := pattern.(string)
					final = append(final, strings.ToLower(pat))
				}
				sort.Strings(final)
				output.Meta[strings.ToLower(header)] = final
			}
		}

		// Use reflection type switch for determining "Implies" tag type
		if fingerprint.Implies != nil {
			v := reflect.ValueOf(fingerprint.Implies)

			switch v.Kind() {
			case reflect.String:
				data := v.Interface().(string)
				output.Implies = append(output.Implies, data)
			case reflect.Slice:
				data := v.Interface().([]interface{})
				for _, pattern := range data {
					pat := pattern.(string)
					output.Implies = append(output.Implies, pat)
				}
			}

			sort.Strings(output.Implies)
		}

		// Use reflection type switch for determining CSS tag type
		if fingerprint.CSS != nil {
			v := reflect.ValueOf(fingerprint.CSS)

			switch v.Kind() {
			case reflect.String:
				data := v.Interface().(string)
				output.CSS = append(output.CSS, data)
			case reflect.Slice:
				data := v.Interface().([]interface{})
				for _, pattern := range data {
					pat := pattern.(string)
					output.CSS = append(output.CSS, pat)
				}
			}

			sort.Strings(output.CSS)
		}

		// Only add if the fingerprint is valid
		outputFingerprints.Apps[app] = output
	}
	return outputFingerprints
}
