package wappalyzer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_All_Match_Paths(t *testing.T) {
	wappalyzer, err := New()
	require.NoError(t, err, "could not create wappalyzer")

	matches := wappalyzer.Fingerprint(map[string][]string{
		"Server": {"Apache/2.4.29"},
	}, []byte(""))
	require.NotNil(t, matches, "could not get matches")
	require.Equal(t, map[string]struct{}{"Apache HTTP Server:2.4.29": struct{}{}}, matches, "could not match apache")
}

func Test_New_Panicking_Regex(t *testing.T) {
	matcher, err := ParsePattern("([\\d\\.]+)\\;version:\\1\\;confidence:0")
	require.NotNil(t, matcher, "could create invalid version regex")
	require.NoError(t, err, "could create invalid version regex")
}

func TestVersionRegex(t *testing.T) {
	regex, err := ParsePattern("JBoss(?:-([\\d.]+))?\\;confidence:50\\;version:\\1")
	require.NoError(t, err, "could not create version regex")

	matched, version := regex.Evaluate("JBoss-2.3.9")
	require.True(t, matched, "could not get version regex match")
	require.Equal(t, "2.3.9", version, "could not get correct version")

	t.Run("confidence-only", func(t *testing.T) {
		_, err := ParsePattern("\\;confidence:50")
		require.NoError(t, err, "could create invalid version regex")
	})

	t.Run("blank", func(t *testing.T) {
		matcher, err := ParsePattern("")
		require.NoError(t, err, "could create invalid version regex")

		matched, _ := matcher.Evaluate("JBoss-2.3.9")
		require.True(t, matched, "should match anything")
	})
}
