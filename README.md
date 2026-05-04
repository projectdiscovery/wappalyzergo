# Wappalyzergo

A high performance port of the Wappalyzer Technology Detection Library to Go. Inspired by [Webanalyze](https://github.com/rverton/webanalyze).

Uses data from 
- https://github.com/enthec/webappanalyzer
- https://github.com/HTTPArchive/wappalyzer

## Features

- Very simple and easy to use, with clean codebase.
- Normalized regexes + auto-updating database of wappalyzer fingerprints.
- Optimized for performance: parsing HTML manually for best speed.

### Using *go install*

```sh
go install -v github.com/projectdiscovery/wappalyzergo/cmd/update-fingerprints@latest
```

After this command *wappalyzergo* library source will be in your current go.mod.

## Example
Usage Example:

### 1. Static Fingerprinting (High Speed, HTML & Headers only)

```go
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

func main() {
	resp, err := http.DefaultClient.Get("https://www.hackerone.com")
	if err != nil {
		log.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body) // Ignoring error for example

	wappalyzerClient, err := wappalyzer.New()
	fingerprints := wappalyzerClient.Fingerprint(resp.Header, data)
	fmt.Printf("%v\n", fingerprints)

	// Output: map[Acquia Cloud Platform:{} Amazon EC2:{} Apache:{} Cloudflare:{} Drupal:{} PHP:{} Percona:{} React:{} Varnish:{}]
}
```

### 2. Headless Fingerprinting (Highly Accurate, checks DOM + JS Globals)

If your target runs React, Next.js, or other front-end UI frameworks, standard HTTP requests will only retrieve an empty `<div id="root">`. Use `FingerprintURL` via Headless Chrome to capture real application fingerprints.

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/chromedp/chromedp"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

func main() {
	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		log.Fatal(err)
	}

	// 1. Create a headless browser context
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	ctx, cancelTimeout := context.WithTimeout(ctx, 15*time.Second)
	defer cancelTimeout()

	// 2. Fetch via headless Chrome to evaluate JS/DOM globals accurately
	headlessFingerprints, err := wappalyzerClient.FingerprintURL(ctx, "https://www.hackerone.com")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Dynamic Fingerprints: %v\n", headlessFingerprints)

	// 3. Map categories efficiently in memory without making 2nd browser request
	headlessFingerprintsWithCats := wappalyzerClient.EnrichWithCats(headlessFingerprints)
	fmt.Printf("Categories: %v\n", headlessFingerprintsWithCats)

	// Output: map[Acquia Cloud Platform:{} Amazon EC2:{} Apache:{} Cloudflare:{} Drupal:{} PHP:{} Percona:{} React:{} Varnish:{}]
}
```
