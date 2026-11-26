package dryrun

import (
	"bytes"
	"io"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func demoPath(name string) string {
	return filepath.Join("..", "..", "..", "demo", "dryrun", name)
}

func TestExecute_ThreeTemplatesDryRunAndEnforceParity(t *testing.T) {
	manifest := demoPath("acceptance.yaml")

	var dryBuffer bytes.Buffer

	code, err := Execute(&dryBuffer, []string{manifest}, "", Options{})
	require.NoError(t, err)
	require.Equal(t, 0, code, "dry-run must not block")

	dryOutput := dryBuffer.String()
	require.Contains(t, dryOutput, "k8srequiredlabels")
	require.Contains(t, dryOutput, "Namespace/bad-ns")
	require.Contains(t, dryOutput, "Pod/default/pod-latest")
	require.Contains(t, dryOutput, "Pod/default/pod-bad-registry")
	require.Contains(t, dryOutput, "DRY RUN")

	var enforceBuffer bytes.Buffer

	enforceCode, err := Execute(&enforceBuffer, []string{manifest}, "", Options{Enforce: true})
	require.NoError(t, err)
	require.Equal(t, 1, enforceCode, "enforcement must reject the same resources")
	require.Contains(t, enforceBuffer.String(), "ENFORCE")

	var jsonBuffer bytes.Buffer

	jsonCode, err := Execute(&jsonBuffer, []string{manifest}, "json", Options{})
	require.NoError(t, err)
	require.Equal(t, 0, jsonCode)
	require.Contains(t, jsonBuffer.String(), `"mode": "dryrun"`)
	require.Contains(t, jsonBuffer.String(), `"wouldDeny": true`)
}

func TestExecute_CheckOnlyCatchesBrokenTemplate(t *testing.T) {
	broken := demoPath("broken-template.yaml")

	code, err := Execute(io.Discard, []string{broken}, "", Options{CheckOnly: true})
	require.NoError(t, err)
	require.Equal(t, 2, code)

	var buffer bytes.Buffer

	strictCode, strictErr := Execute(&buffer, []string{broken}, "", Options{StrictCheck: true})
	require.NoError(t, strictErr)
	require.Equal(t, 2, strictCode)
	require.Contains(t, buffer.String(), `[FAIL] brokenrulename`)
}
