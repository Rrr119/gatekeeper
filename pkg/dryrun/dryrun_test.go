package dryrun_test

import (
	"context"
	"sort"
	"testing"

	"github.com/open-policy-agent/gatekeeper/v3/pkg/dryrun"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/gator/reader"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const requiredLabelsTemplate = `
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        openAPIV3Schema:
          type: object
          properties:
            labels:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels

        violation[{"msg": msg}] {
          required := {label | label := input.parameters.labels[_]}
          provided := {label | input.review.object.metadata.labels[label]}
          missing := required - provided
          count(missing) > 0
          msg := sprintf("you must provide labels %v", [missing])
        }
`

const disallowLatestTemplate = `
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sdisallowlatest
spec:
  crd:
    spec:
      names:
        kind: K8sDisallowLatest
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sdisallowlatest

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          endswith(container.image, ":latest")
          msg := sprintf("container %q must not use the latest tag", [container.name])
        }
`

const allowedRegistriesTemplate = `
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8sallowedregistries
spec:
  crd:
    spec:
      names:
        kind: K8sAllowedRegistries
      validation:
        openAPIV3Schema:
          type: object
          properties:
            registries:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sallowedregistries

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not image_allowed(container.image, input.parameters.registries)
          msg := sprintf("image %q is not from an allowed registry", [container.image])
        }

        image_allowed(image, registries) {
          registry := registries[_]
          startswith(image, registry)
        }
`

const constraintsYAML = `
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: ns-must-have-owner
spec:
  enforcementAction: deny
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Namespace"]
  parameters:
    labels: ["owner"]
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sDisallowLatest
metadata:
  name: no-latest-tag
spec:
  enforcementAction: deny
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedRegistries
metadata:
  name: approved-registries
spec:
  enforcementAction: deny
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    registries: ["registry.example.com/"]
`

const resourcesYAML = `
apiVersion: v1
kind: Namespace
metadata:
  name: good-ns
  labels:
    owner: team-a
---
apiVersion: v1
kind: Namespace
metadata:
  name: bad-ns
---
apiVersion: v1
kind: Pod
metadata:
  name: pod-good
  namespace: default
spec:
  containers:
    - name: app
      image: registry.example.com/app:v1.2.3
---
apiVersion: v1
kind: Pod
metadata:
  name: pod-latest
  namespace: default
spec:
  containers:
    - name: app
      image: registry.example.com/app:latest
---
apiVersion: v1
kind: Pod
metadata:
  name: pod-bad-registry
  namespace: default
spec:
  containers:
    - name: sidecar
      image: evil.example.io/tool:v0.9
`

// acceptanceManifests returns the exact acceptance scenario: 3 templates,
// 3 constraints and 5 resources.
func acceptanceManifests(t *testing.T) []byte {
	t.Helper()

	return []byte(requiredLabelsTemplate + "\n---\n" +
		disallowLatestTemplate + "\n---\n" +
		allowedRegistriesTemplate + "\n---\n" +
		constraintsYAML + "\n---\n" +
		resourcesYAML)
}

func TestAcceptance_ThreeTemplates_DryRunListsButDoesNotBlock(t *testing.T) {
	ctx := context.Background()
	manifests := acceptanceManifests(t)

	parsed, err := dryrun.Parse(manifests)
	require.NoError(t, err)
	require.Len(t, parsed.Templates, 3, "expected exactly 3 ConstraintTemplates")
	require.Len(t, parsed.Constraints, 3)
	require.Len(t, parsed.Resources, 5)

	runner, err := dryrun.NewRunner(ctx, dryrun.WithManifest(parsed))
	require.NoError(t, err)

	// Self-check: all three templates are valid and carry violation rules.
	checks := runner.Checks()
	require.Len(t, checks, 3)

	for _, check := range checks {
		require.Equalf(t, dryrun.CheckPass, check.Status, "template %q should pass self-check: %v", check.Name, check.Errors)
		require.Truef(t, check.HasViolationRule, "template %q should expose a violation rule", check.Name)
		require.Empty(t, check.Errors)
	}

	dryReport, err := runner.DryRun(ctx)
	require.NoError(t, err)

	// Dry-run never blocks.
	require.Equal(t, dryrun.ModeDryRun, dryReport.Mode)
	require.True(t, dryReport.Allowed, "dry-run must never reject admission")
	require.Empty(t, dryReport.Errors, "evaluation should not produce errors: %+v", dryReport.Errors)

	// The violation resource list names exactly the three bad resources.
	wantDenied := []string{
		"Namespace bad-ns",
		"Pod default/pod-bad-registry",
		"Pod default/pod-latest",
	}
	require.Equal(t, wantDenied, dryReport.DeniedRefs())
	require.Equal(t, wantDenied, sortedStrings(dryReport.ViolatingRefs()))

	byName := reportsByName(dryReport)
	require.False(t, byName["good-ns"].WouldDeny)
	require.False(t, byName["pod-good"].WouldDeny)
	require.True(t, byName["bad-ns"].WouldDeny)
	require.True(t, byName["pod-latest"].WouldDeny)
	require.True(t, byName["pod-bad-registry"].WouldDeny)

	require.NotEmpty(t, byName["bad-ns"].Messages)
	require.NotEmpty(t, byName["pod-latest"].Messages)
	require.NotEmpty(t, byName["pod-bad-registry"].Messages)

	// Enforcing rejects exactly the dry-run predicted set.
	enforceReport, err := runner.Enforce(ctx)
	require.NoError(t, err)
	require.Equal(t, dryrun.ModeEnforce, enforceReport.Mode)
	require.False(t, enforceReport.Allowed, "enforcement must reject the violating resources")
	require.Equal(t, dryReport.DeniedRefs(), enforceReport.DeniedRefs(),
		"enforcement denials must match dry-run predictions")

	for i := range dryReport.Resources {
		dryResource := dryReport.Resources[i]
		enforceResource := enforceReport.Resources[i]
		require.Equal(t, dryResource.Resource, enforceResource.Resource)
		require.Equal(t, dryResource.WouldDeny, enforceResource.WouldDeny,
			"dry-run/enforce mismatch for %s", dryResource.Resource)
	}

	// Package-level entry points tell the same story from raw manifests.
	topDry, err := dryrun.DryRun(ctx, manifests)
	require.NoError(t, err)
	require.True(t, topDry.Allowed)
	require.Equal(t, wantDenied, topDry.DeniedRefs())

	topEnforce, err := dryrun.Enforce(ctx, manifests)
	require.NoError(t, err)
	require.False(t, topEnforce.Allowed)
	require.Equal(t, wantDenied, topEnforce.DeniedRefs())
}

func TestSelfCheck_DetectsSilentAllowAllTemplate(t *testing.T) {
	ctx := context.Background()

	// Rule is misspelled "violations", so Gatekeeper never sees a violation
	// and every resource is admitted.
	broken := []byte(`
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: brokenrulename
spec:
  crd:
    spec:
      names:
        kind: BrokenRuleName
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package brokenrulename

        violations[{"msg": msg}] {
          msg := "this never fires"
        }
`)

	checks, err := dryrun.SelfCheck(ctx, broken)
	require.NoError(t, err)
	require.Len(t, checks, 1)
	require.Equal(t, dryrun.CheckFail, checks[0].Status)
	require.False(t, checks[0].HasViolationRule)
	require.NotEmpty(t, checks[0].Errors)

	// A compile error is also surfaced loudly.
	compileError := []byte(`
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: compileerror
spec:
  crd:
    spec:
      names:
        kind: CompileError
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package compileerror

        violation[{"msg": msg}] {
          this_reference_is_undefined_and_invalid[
          msg := "boom"
        }
`)

	compileChecks, err := dryrun.SelfCheck(ctx, compileError)
	require.NoError(t, err)
	require.Len(t, compileChecks, 1)
	require.Equal(t, dryrun.CheckFail, compileChecks[0].Status)
	require.NotEmpty(t, compileChecks[0].Errors)
}

func TestCheckTemplate_ProbeCatchesSemanticFailOpen(t *testing.T) {
	ctx := context.Background()

	parsed, err := dryrun.Parse([]byte(requiredLabelsTemplate))
	require.NoError(t, err)
	require.Len(t, parsed.Templates, 1)

	missingLabelNS := mustUnstructured(t, `
apiVersion: v1
kind: Namespace
metadata:
  name: probe-bad
`)

	// A positive probe proves the template actually rejects bad input.
	check := dryrun.CheckTemplate(ctx, parsed.Templates[0], dryrun.Probe{
		Name:          "namespace missing owner label",
		Resource:      missingLabelNS,
		Parameters:    map[string]interface{}{"labels": []interface{}{"owner"}},
		WantViolation: true,
	})
	require.Equal(t, dryrun.CheckPass, check.Status, "errors=%v probes=%+v", check.Errors, check.Probes)
	require.Len(t, check.Probes, 1)
	require.True(t, check.Probes[0].Pass)
	require.Equal(t, 1, check.Probes[0].ViolationCount)
}

func TestDryRun_TemplateOnlyTrialRunSynthesizesConstraint(t *testing.T) {
	ctx := context.Background()

	// No Constraint manifest is supplied: the runner trial-runs the template
	// directly with an all-matching default constraint.
	report, err := dryrun.DryRun(ctx, []byte(disallowLatestTemplate), []byte(resourcesYAML))
	require.NoError(t, err)
	require.True(t, report.Allowed)
	require.Empty(t, report.Errors)
	require.Equal(t, []string{"Pod default/pod-latest"}, report.DeniedRefs())

	enforceReport, err := dryrun.Enforce(ctx, []byte(disallowLatestTemplate), []byte(resourcesYAML))
	require.NoError(t, err)
	require.False(t, enforceReport.Allowed)
	require.Equal(t, report.DeniedRefs(), enforceReport.DeniedRefs())
}

func reportsByName(report *dryrun.Report) map[string]dryrun.ResourceReport {
	out := make(map[string]dryrun.ResourceReport, len(report.Resources))
	for i := range report.Resources {
		out[report.Resources[i].Resource.Name] = report.Resources[i]
	}

	return out
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)

	return out
}

func mustUnstructured(t *testing.T, yaml string) *unstructured.Unstructured {
	t.Helper()

	obj, err := reader.ReadUnstructured([]byte(yaml))
	require.NoError(t, err)
	require.NotNil(t, obj)

	return obj
}
