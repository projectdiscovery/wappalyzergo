package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"reflect"
	"strings"

	jsoniter "github.com/json-iterator/go"
)

var (
	fingerprints = flag.String("fingerprints", "../../fingerprints_data.json", "File to write wappalyzer fingerprints to")
)

// Fingerprints contains a map of fingerprints for tech detection
type Fingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]Fingerprint `json:"technologies"`
}

// Fingerprint is a single piece of information about a tech
type Fingerprint struct {
	CSS     interface{}            `json:"css"`
	Cookies map[string]string      `json:"cookies"`
	JS      map[string]string      `json:"js"`
	Headers map[string]string      `json:"headers"`
	HTML    interface{}            `json:"html"`
	Script  interface{}            `json:"script"`
	Meta    map[string]interface{} `json:"meta"`
	Implies interface{}            `json:"implies"`
}

// OutputFingerprints contains a map of fingerprints for tech detection
// optimized and validated for the tech detection package
type OutputFingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]OutputFingerprint `json:"apps"`
}

// OutputFingerprint is a single piece of information about a tech validated and normalized
type OutputFingerprint struct {
	Cookies map[string]string   `json:"cookies,omitempty"`
	JS      []string            `json:"js,omitempty"`
	Headers map[string]string   `json:"headers,omitempty"`
	HTML    []string            `json:"html,omitempty"`
	Script  []string            `json:"script,omitempty"`
	CSS     []string            `json:"css,omitempty"`
	Meta    map[string][]string `json:"meta,omitempty"`
	Implies []string            `json:"implies,omitempty"`
}

const fingerprintURL = "https://raw.githubusercontent.com/AliasIO/wappalyzer/master/src/technologies/%s.json"

func makeFingerprintURLs() []string {
	files := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "_"}

	var fingerprints []string
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

	fingerprintsFile, err := os.OpenFile(*fingerprints, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		log.Fatalf("Could not open fingerprints file %s: %s\n", *fingerprints, err)
	}

	data, err := jsoniter.Marshal(outputFingerprints)
	if err != nil {
		log.Fatalf("Could not marshal fingerprints: %s\n", err)
	}
	_, _ = fingerprintsFile.Write(data)
	fingerprintsFile.Close()
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

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	fingerprintsOld := &Fingerprints{}
	err = jsoniter.NewDecoder(bytes.NewReader(data)).Decode(&fingerprintsOld.Apps)
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
			Cookies: make(map[string]string),
			Headers: make(map[string]string),
			Meta:    make(map[string][]string),
		}

		for cookie, value := range fingerprint.Cookies {
			output.Cookies[strings.ToLower(cookie)] = strings.ToLower(value)
		}
		for js := range fingerprint.JS {
			output.JS = append(output.JS, strings.ToLower(js))
		}
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
		}

		// Use reflection type switch for determining Script tag type
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
		}
		// Only add if the fingerprint is valid
		outputFingerprints.Apps[app] = output
	}
	return outputFingerprints
}
