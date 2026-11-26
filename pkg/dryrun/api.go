package dryrun

import (
	"context"
	"fmt"
)

// DryRun parses the supplied multi-document YAML/JSON manifests (existing
// ConstraintTemplates, Constraints and Kubernetes resources) and evaluates
// every resource without blocking anything.
//
// The returned [Report.DeniedResources] lists exactly the resources that
// [Enforce] (and Gatekeeper's validating webhook once live) would reject.
func DryRun(ctx context.Context, manifests ...[]byte) (*Report, error) {
	runner, manifest, err := runnerFromManifests(ctx, manifests)
	if err != nil {
		return nil, err
	}

	return runner.DryRun(ctx, manifest.Resources...)
}

// Enforce parses the supplied manifests and evaluates every resource as if
// the policies were live: [Report.Allowed] is false when at least one resource
// carries a deny violation. It uses the exact same evaluation path as
// [DryRun].
func Enforce(ctx context.Context, manifests ...[]byte) (*Report, error) {
	runner, manifest, err := runnerFromManifests(ctx, manifests)
	if err != nil {
		return nil, err
	}

	return runner.Enforce(ctx, manifest.Resources...)
}

// Check is an alias for [SelfCheck]: it parses manifests and self-checks
// every contained ConstraintTemplate.
func Check(ctx context.Context, manifests ...[]byte) ([]TemplateCheck, error) {
	return SelfCheck(ctx, manifests...)
}

// NewRunnerFromManifests parses manifests and builds a [Runner] backed by an
// isolated constraint client. Callers can reuse the runner to compare DryRun
// and Enforce outcomes over the same compiled policies.
func NewRunnerFromManifests(ctx context.Context, manifests ...[]byte) (*Runner, *Manifest, error) {
	return runnerFromManifests(ctx, manifests)
}

func runnerFromManifests(ctx context.Context, manifests [][]byte) (*Runner, *Manifest, error) {
	manifest, err := Parse(manifests...)
	if err != nil {
		return nil, nil, err
	}

	runner, err := NewRunner(ctx, WithManifest(manifest))
	if err != nil {
		return nil, nil, fmt.Errorf("dryrun: building runner: %w", err)
	}

	return runner, manifest, nil
}
