package wappalyzer

import (
	_ "embed"
)

var (
	//go:embed fingerprints_data.json
	fingerprints string
	//go:embed technology_icons.json
	technologyIcons string
)
