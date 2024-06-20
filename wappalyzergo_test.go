package wappalyzer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCookiesDetect(t *testing.T) {
	wappalyzer, err := New()
	require.Nil(t, err, "could not create wappalyzer")

	matches := wappalyzer.Fingerprint(map[string][]string{
		"Set-Cookie": {"_uetsid=ABCDEF"},
	}, []byte(""))
	require.Contains(t, matches, "Microsoft Advertising", "Could not get correct match")

	t.Run("position", func(t *testing.T) {
		wappalyzerClient, _ := New()

		fingerprints := wappalyzerClient.Fingerprint(map[string][]string{
			"Set-Cookie": {"path=/; jsessionid=111; path=/, jsessionid=111;"},
		}, []byte(""))
		fingerprints1 := wappalyzerClient.Fingerprint(map[string][]string{
			"Set-Cookie": {"jsessionid=111; path=/, XSRF-TOKEN=; expires=test, path=/ laravel_session=eyJ*"},
		}, []byte(""))

		require.Equal(t, map[string]struct{}{"Java": {}}, fingerprints, "could not get correct fingerprints")
		require.Equal(t, map[string]struct{}{"Java": {}, "Laravel": {}, "PHP": {}}, fingerprints1, "could not get correct fingerprints")
	})
}

func TestHeadersDetect(t *testing.T) {
	wappalyzer, err := New()
	require.Nil(t, err, "could not create wappalyzer")

	matches := wappalyzer.Fingerprint(map[string][]string{
		"Server": {"now"},
	}, []byte(""))

	require.Contains(t, matches, "Vercel", "Could not get correct match")
}

func TestBodyDetect(t *testing.T) {
	wappalyzer, err := New()
	require.Nil(t, err, "could not create wappalyzer")

	t.Run("meta", func(t *testing.T) {
		matches := wappalyzer.Fingerprint(map[string][]string{}, []byte(`<html>
<head>
<meta name="generator" content="mura cms 1">
</head>
</html>`))
		require.Contains(t, matches, "Mura CMS:1", "Could not get correct match")
	})

	t.Run("html-implied", func(t *testing.T) {
		matches := wappalyzer.Fingerprint(map[string][]string{}, []byte(`<html data-ng-app="rbschangeapp">
<head>
</head>
<body>
</body>
</html>`))
		require.Contains(t, matches, "AngularJS", "Could not get correct implied match")
		require.Contains(t, matches, "PHP", "Could not get correct implied match")
		require.Contains(t, matches, "Proximis Unified Commerce", "Could not get correct match")
	})
}

func TestUniqueFingerprints(t *testing.T) {
	fingerprints := NewUniqueFingerprints()
	fingerprints.SetIfNotExists("test", "", 100)
	require.Equal(t, map[string]struct{}{"test": {}}, fingerprints.GetValues(), "could not get correct values")

	t.Run("linear", func(t *testing.T) {
		fingerprints.SetIfNotExists("new", "2.3.5", 100)
		require.Equal(t, map[string]struct{}{"test": {}, "new:2.3.5": {}}, fingerprints.GetValues(), "could not get correct values")

		fingerprints.SetIfNotExists("new", "", 100)
		require.Equal(t, map[string]struct{}{"test": {}, "new:2.3.5": {}}, fingerprints.GetValues(), "could not get correct values")
	})

	t.Run("opposite", func(t *testing.T) {
		fingerprints.SetIfNotExists("another", "", 100)
		require.Equal(t, map[string]struct{}{"test": {}, "new:2.3.5": {}, "another": {}}, fingerprints.GetValues(), "could not get correct values")

		fingerprints.SetIfNotExists("another", "2.3.5", 100)
		require.Equal(t, map[string]struct{}{"test": {}, "new:2.3.5": {}, "another:2.3.5": {}}, fingerprints.GetValues(), "could not get correct values")
	})

	t.Run("confidence", func(t *testing.T) {
		f := NewUniqueFingerprints()
		f.SetIfNotExists("test", "", 0)
		require.Equal(t, map[string]struct{}{}, f.GetValues(), "could not get correct values")

		f.SetIfNotExists("test", "2.36.4", 100)
		require.Equal(t, map[string]struct{}{"test:2.36.4": {}}, f.GetValues(), "could not get correct values")
	})
}

func Test_FingerprintWithInfo(t *testing.T) {
	wappalyzer, err := New()
	require.Nil(t, err, "could not create wappalyzer")

	name := "Liferay:7.3.5"
	matches := wappalyzer.FingerprintWithInfo(map[string][]string{
		"liferay-portal": {"testserver 7.3.5"},
	}, []byte(""))
	require.Contains(t, matches, name, "Could not get correct match")

	value := matches[name]
	require.Equal(t, "cpe:2.3:a:liferay:liferay_portal:*:*:*:*:*:*:*:*", value.CPE, "could not get correct name")
	require.Equal(t, "https://www.liferay.com/", value.Website, "could not get correct website")
	require.Equal(t, "Liferay is an open-source company that provides free documentation and paid professional service to users of its software.", value.Description, "could not get correct description")
	require.Equal(t, "Liferay.svg", value.Icon, "could not get correct icon")
	require.ElementsMatch(t, []string{"CMS"}, value.Categories, "could not get correct categories")
}
