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

	// Create context for Chromedp
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	// Optionally add a timeout
	ctx, cancelTimeout := context.WithTimeout(ctx, 15*time.Second)
	defer cancelTimeout()

	headlessFingerprints, err := wappalyzerClient.FingerprintURL(ctx, "https://example.com")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%v\n", headlessFingerprints)

	// To avoid making a second headless request, we enrich the results from the first fetch
	headlessFingerprintsWithCats := wappalyzerClient.EnrichWithCats(headlessFingerprints)

	fmt.Printf("%v\n", headlessFingerprintsWithCats)
}
