package wappalyzer

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCookiesDetect(t *testing.T) {
	wappalyzer, err := New()
	require.Nil(t, err, "could not create wappalyzer")

	matches := wappalyzer.Fingerprint("", map[string][]string{
		"Set-Cookie": {"_uetsid=ABCDEF"},
	}, []byte(""))

	require.Contains(t, matches[0].Name, "Microsoft Advertising", "Could not get correct match")

	t.Run("position", func(t *testing.T) {
		wappalyzerClient, _ := New()

		fingerprints := wappalyzerClient.Fingerprint("", map[string][]string{
			"Set-Cookie": {"path=/; jsessionid=111; path=/, jsessionid=111;"},
		}, []byte(""))
		fingerprints1 := wappalyzerClient.Fingerprint("", map[string][]string{
			"Set-Cookie": {"jsessionid=111; path=/, XSRF-TOKEN=; expires=test, path=/ laravel_session=eyJ*"},
		}, []byte(""))

		require.Equal(t, []Technology{
			{Name: "Java"},
		}, fingerprints, "could not get correct fingerprints")
		require.True(t, IsEqual(
			[]Technology{
				{Name: "Java"}, {Name: "Laravel"}, {Name: "PHP"},
			}, fingerprints1), "could not get correct fingerprints")
	})
}

func TestHeadersDetect(t *testing.T) {
	wappalyzer, err := New()
	require.Nil(t, err, "could not create wappalyzer")

	matches := wappalyzer.Fingerprint("", map[string][]string{
		"Server": {"now"},
	}, []byte(""))

	require.Contains(t, matches, Technology{Name: "Vercel"}, "Could not get correct match")
}

func TestBodyDetect(t *testing.T) {
	wappalyzer, err := New()
	require.Nil(t, err, "could not create wappalyzer")

	t.Run("meta", func(t *testing.T) {
		matches := wappalyzer.Fingerprint("", map[string][]string{}, []byte(`<html>
<head>
<meta name="generator" content="mura cms 1">
</head>
</html>`))
		//require.True(t, isExists("Mura CMS:1", matches), "Expected technology %q not found in matches", "Mura CMS:1")
		require.Contains(t, matches, Technology{Name: "Mura CMS", Version: "1"}, "Could not get correct match")
	})

	t.Run("html-implied", func(t *testing.T) {
		matches := wappalyzer.Fingerprint("", map[string][]string{}, []byte(`<html data-ng-app="rbschangeapp">
<head>
</head>
<body>
</body>
</html>`))
		require.Contains(t, matches, Technology{Name: "AngularJS"}, "Could not get correct implied match")
		require.Contains(t, matches, Technology{Name: "PHP"}, "Could not get correct implied match")
		require.Contains(t, matches, Technology{Name: "Proximis Unified Commerce"}, "Could not get correct match")
	})
}

func TestUniqueFingerprints(t *testing.T) {
	fingerprints := newUniqueFingerprints()
	fingerprints.setIfNotExists("test")
	require.Equal(t, map[string]interface{}{"test": interface{}(nil)}, fingerprints.getValues(), "could not get correct values")

	t.Run("linear", func(t *testing.T) {
		fingerprints.setIfNotExists("new:2.3.5")
		require.Equal(t, map[string]interface{}{"test": interface{}(nil), "new:2.3.5": interface{}(nil)}, fingerprints.getValues(), "could not get correct values")

		fingerprints.setIfNotExists("new")
		require.Equal(t, map[string]interface{}{"test": interface{}(nil), "new:2.3.5": interface{}(nil)}, fingerprints.getValues(), "could not get correct values")
	})

	t.Run("opposite", func(t *testing.T) {
		fingerprints.setIfNotExists("another")
		require.Equal(t, map[string]interface{}{"test": interface{}(nil), "new:2.3.5": interface{}(nil), "another": interface{}(nil)}, fingerprints.getValues(), "could not get correct values")

		fingerprints.setIfNotExists("another:2.3.5")
		require.Equal(t, map[string]interface{}{"test": interface{}(nil), "new:2.3.5": interface{}(nil), "another:2.3.5": interface{}(nil)}, fingerprints.getValues(), "could not get correct values")
	})
}

func IsEqual(slice1, slice2 []Technology) bool {
	if len(slice1) != len(slice2) {
		return false
	}

	// Sort both slices
	sort.Slice(slice1, func(i, j int) bool {
		return slice1[i].Name < slice1[j].Name
	})
	sort.Slice(slice2, func(i, j int) bool {
		return slice2[i].Name < slice2[j].Name
	})

	for i := range slice1 {
		if slice1[i] != slice2[i] {
			return false
		}
	}

	return true
}
