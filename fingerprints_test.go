package wappalyzer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVersionRegex(t *testing.T) {
	regex, err := newVersionRegex("JBoss(?:-([\\d.]+))?\\;confidence:50\\;version:\\1")
	require.NoError(t, err, "could not create version regex")

	matched, version := regex.MatchString("JBoss-2.3.9")
	require.True(t, matched, "could not get version regex match")
	require.Equal(t, "2.3.9", version, "could not get correct version")

	t.Run("confidence-only", func(t *testing.T) {
		_, err := newVersionRegex("\\;confidence:50")
		require.NoError(t, err, "could create invalid version regex")
	})
}
