package dryrun_test

import (
	"context"
	"testing"

	"github.com/open-policy-agent/gatekeeper/v3/pkg/dryrun"
	"github.com/stretchr/testify/require"
)

func TestEnforce_RespectsDryRunEnforcementAction(t *testing.T) {
	ctx := context.Background()

	// The constraint uses Gatekeeper's native enforcementAction: dryrun.
	// Violations must be listed, but nothing is denied.
	manifest := []byte(disallowLatestTemplate + `
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sDisallowLatest
metadata:
  name: no-latest-tag-shadow
spec:
  enforcementAction: dryrun
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
---
apiVersion: v1
kind: Pod
metadata:
  name: pod-latest-shadow
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:latest
`)

	dryReport, err := dryrun.DryRun(ctx, manifest)
	require.NoError(t, err)
	require.Len(t, dryReport.ViolatingResources, 1)
	require.False(t, dryReport.ViolatingResources[0].WouldDeny)
	require.Empty(t, dryReport.DeniedResources)
	require.True(t, dryReport.Allowed)

	for _, violation := range dryReport.Violations {
		require.Equal(t, dryrun.ActionDryrun, violation.EnforcementAction)
		require.False(t, violation.WouldDeny)
	}

	// Even "enforce" mode does not reject a constraint whose action is dryrun.
	enforceReport, err := dryrun.Enforce(ctx, manifest)
	require.NoError(t, err)
	require.True(t, enforceReport.Allowed)
	require.Empty(t, enforceReport.DeniedResources)
	require.Len(t, enforceReport.ViolatingResources, 1)
}
