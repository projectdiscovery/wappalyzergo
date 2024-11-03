# Wappalyzergo

A high performance port of the Wappalyzer Technology Detection Library to Go. Inspired by [Webanalyze](https://github.com/rverton/webanalyze).

Uses data from https://github.com/AliasIO/wappalyzer

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

``` go
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

## Docker

### Building the Docker image

To build the Docker image, run the following command:

```sh
docker build -t wappalyzergo .
```

### Running the Docker container

To run the Docker container, use the following command:

```sh
docker run --rm -v $(pwd):/app wappalyzergo --fingerprints /app/fingerprints_data.json
```

### Using Docker Compose

You can also use Docker Compose to build and run the Docker container. Create a `docker-compose.yml` file with the following content:

```yaml
version: '3.8'

services:
  wappalyzergo:
    build:
      context: .
      dockerfile: Dockerfile
    entrypoint: ["./main"]
    command: ["--fingerprints", "/app/fingerprints_data.json"]
    volumes:
      - .:/app
```

To build and run the Docker container using Docker Compose, run the following command:

```sh
docker-compose up --build
```

### Passing parameters to the Docker container

You can pass parameters to the Docker container by appending them to the `docker run` or `docker-compose up` command. For example:

```sh
docker run --rm -v $(pwd):/app wappalyzergo --fingerprints /app/fingerprints_data.json --some-other-parameter value
```

or

```sh
docker-compose run wappalyzergo --some-other-parameter value
```
