package main

import (
    "flag"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "net/url"
    "os"
    "strconv"

    wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

func main() {
    port := flag.Int("port", 8087, "the port number to listen on")
    flag.Parse()

    if envPort := os.Getenv("PORT"); envPort != "" {
        *port, _ = strconv.Atoi(envPort)
    }

    log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
    log.SetOutput(os.Stdout)

    var transport *http.Transport
    proxyURL, err := url.Parse(os.Getenv("HTTP_PROXY"))
    if err != nil {
        log.Printf("error parsing HTTP_PROXY: %v", err)
    } else {
        transport = &http.Transport{
            Proxy: http.ProxyURL(proxyURL),
        }
    }

    var client *http.Client
    if transport != nil {
        client = &http.Client{Transport: transport}
    } else {
        client = &http.Client{}
    }

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        url := r.URL.Query().Get("url")
        if url == "" {
            http.Error(w, "url parameter is missing", http.StatusBadRequest)
            return
        }

        req, err := http.NewRequest("GET", url, nil)
        if err != nil {
            log.Printf("error creating GET request for %s: %v", url, err)
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        resp, err := client.Do(req)
        if err != nil {
            log.Printf("error getting %s: %v", url, err)
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        defer resp.Body.Close()

        data, err := ioutil.ReadAll(resp.Body)
        if err != nil {
            log.Printf("error reading response body from %s: %v", url, err)
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        wappalyzerClient, err := wappalyzer.New()
        if err != nil {
            log.Printf("error creating wappalyzer client: %v", err)
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        fingerprints := wappalyzerClient.Fingerprint(resp.Header, data)
        fmt.Fprintf(w, "%v\n", fingerprints)
    })

    log.Printf("Listening on port %d...", *port)
    log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), nil))
}
