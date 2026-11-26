package dryrun

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/reviews"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/target"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/util"
	opaparser "github.com/open-policy-agent/opa/v1/ast"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Report error scopes.
const (
	// ScopeTemplate marks a template-level failure.
	ScopeTemplate = "template"
	// ScopeConstraint marks a constraint-level failure.
	ScopeConstraint = "constraint"
	// ScopeResource marks a resource review failure.
	ScopeResource = "resource"
	// ScopeData marks an inventory data loading failure.
	ScopeData = "data"
)

// CheckStatus is the outcome of a template self-check.
type CheckStatus string

const (
	// CheckPass means the template compiled and passed structural/probe checks.
	CheckPass CheckStatus = "pass"

	// CheckFail means the template is invalid or proven ineffective.
	CheckFail CheckStatus = "fail"
)

// Probe is a self-check review with an expected outcome. A probe with
// WantViolation set to true is the key guard against "template silently
// allows everything" logic errors: if the probe is not flagged, the check
// fails.
type Probe struct {
	// Name identifies the probe in the result.
	Name string

	// Resource is the resource to review.
	Resource *unstructured.Unstructured

	// Constraint is the constraint to use. When nil, an all-matching default
	// constraint is synthesized from the template and Parameters.
	Constraint *unstructured.Unstructured

	// Parameters are used for the synthesized constraint when Constraint is nil.
	Parameters map[string]interface{}

	// WantViolation asserts that the template must flag the probe resource.
	WantViolation bool
}

// ProbeResult is the outcome of one probe.
type ProbeResult struct {
	Name           string   `json:"name"`
	Pass           bool     `json:"pass"`
	WantViolation  bool     `json:"wantViolation"`
	ViolationCount int      `json:"violationCount"`
	Messages       []string `json:"messages,omitempty"`
	Detail         string   `json:"detail,omitempty"`
}

// TemplateCheck is the self-check result for one ConstraintTemplate.
type TemplateCheck struct {
	// Name is the template name.
	Name string `json:"name"`

	// Kind is the constraint kind declared by the template CRD.
	Kind string `json:"kind,omitempty"`

	// Status is pass or fail.
	Status CheckStatus `json:"status"`

	// HasViolationRule reports whether a recognizable Rego violation rule
	// was found. It is false for CEL-only templates as well.
	HasViolationRule bool `json:"hasViolationRule"`

	// Engines lists the policy engines referenced by the template.
	Engines []string `json:"engines,omitempty"`

	// Errors lists blocking problems, including compile errors.
	Errors []string `json:"errors,omitempty"`

	// Warnings lists non-blocking observations.
	Warnings []string `json:"warnings,omitempty"`

	// Probes contains the probe outcomes.
	Probes []ProbeResult `json:"probes,omitempty"`
}

// OK reports whether the check passed.
func (c *TemplateCheck) OK() bool {
	return c.Status == CheckPass
}

// SelfCheck parses the supplied manifests and runs the structural and
// compilation self-check for every contained ConstraintTemplate. Use
// [CheckTemplate] directly to add behavioral probes.
func SelfCheck(ctx context.Context, docs ...[]byte) ([]TemplateCheck, error) {
	manifest, err := Parse(docs...)
	if err != nil {
		return nil, err
	}

	checks := make([]TemplateCheck, 0, len(manifest.Templates))

	for _, tmpl := range manifest.Templates {
		checks = append(checks, CheckTemplate(ctx, tmpl))
	}

	return checks, nil
}

// CheckTemplate runs the structural, compilation and optional probe checks for
// one template. It never panics on malformed templates; all problems are
// returned in the [TemplateCheck].
func CheckTemplate(ctx context.Context, tmpl *templates.ConstraintTemplate, probes ...Probe) TemplateCheck {
	check := inspectTemplate(tmpl)

	cfg := config{enableCEL: true, enforcementPoint: util.GatorEnforcementPoint}

	client, err := newClient(&cfg)
	if err != nil {
		check.Status = CheckFail
		check.Errors = append(check.Errors, err.Error())

		return check
	}

	if _, err := client.AddTemplate(ctx, tmpl); err != nil {
		check.Status = CheckFail
		check.Errors = append(check.Errors, err.Error())

		return check
	}

	for i, probe := range probes {
		check.Probes = append(check.Probes, runProbe(ctx, tmpl, i, probe))
	}

	for _, probeResult := range check.Probes {
		if !probeResult.Pass {
			check.Status = CheckFail
		}
	}

	return check
}

func runProbe(ctx context.Context, tmpl *templates.ConstraintTemplate, index int, probe Probe) ProbeResult {
	result := ProbeResult{
		Name:          probe.Name,
		WantViolation: probe.WantViolation,
	}

	if result.Name == "" {
		result.Name = fmt.Sprintf("probe-%d", index+1)
	}

	if probe.Resource == nil {
		result.Pass = false
		result.Detail = "probe has no resource"

		return result
	}

	cfg := config{enableCEL: true, enforcementPoint: util.GatorEnforcementPoint}

	client, err := newClient(&cfg)
	if err != nil {
		result.Pass = false
		result.Detail = err.Error()

		return result
	}

	if _, err := client.AddTemplate(ctx, tmpl); err != nil {
		result.Pass = false
		result.Detail = err.Error()

		return result
	}

	constraint := probe.Constraint
	if constraint == nil {
		constraint = DefaultConstraint(tmpl, fmt.Sprintf("selfcheck-probe-%d", index), probe.Parameters)
	}

	if _, err := client.AddConstraint(ctx, constraint); err != nil {
		result.Pass = false
		result.Detail = fmt.Sprintf("adding probe constraint: %v", err)

		return result
	}

	augmented := target.AugmentedUnstructured{Object: *probe.Resource}

	responses, err := client.Review(ctx, augmented, reviews.EnforcementPoint(util.GatorEnforcementPoint))
	if err != nil {
		result.Pass = false
		result.Detail = fmt.Sprintf("review error: %v", err)

		return result
	}

	for _, violationResult := range responses.Results() {
		result.ViolationCount++

		if violationResult.Msg != "" {
			result.Messages = append(result.Messages, violationResult.Msg)
		}
	}

	switch {
	case probe.WantViolation && result.ViolationCount == 0:
		result.Pass = false
		result.Detail = "expected the template to reject this probe resource, but it allowed it; the template may fail open and admit everything"
	case !probe.WantViolation && result.ViolationCount > 0:
		result.Pass = false
		result.Detail = "expected this probe resource to be allowed, but the template flagged it"
	default:
		result.Pass = true
	}

	return result
}

// DefaultConstraint builds an all-matching constraint for a template. It is
// useful for template-only dry-runs and self-check probes.
func DefaultConstraint(tmpl *templates.ConstraintTemplate, name string, parameters map[string]interface{}) *unstructured.Unstructured {
	kind := ""
	if tmpl != nil {
		kind = tmpl.Spec.CRD.Spec.Names.Kind
	}

	if name == "" {
		name = "dryrun-default"
	}

	spec := map[string]interface{}{
		"match": map[string]interface{}{
			"kinds": []interface{}{
				map[string]interface{}{
					"apiGroups": []interface{}{"*"},
					"kinds":     []interface{}{"*"},
				},
			},
		},
	}

	if len(parameters) > 0 {
		spec["parameters"] = parameters
	}

	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "constraints.gatekeeper.sh/v1beta1",
			"kind":       kind,
			"metadata": map[string]interface{}{
				"name": name,
			},
			"spec": spec,
		},
	}
}

func inspectTemplate(tmpl *templates.ConstraintTemplate) TemplateCheck {
	check := TemplateCheck{Status: CheckPass}

	if tmpl == nil {
		check.Status = CheckFail
		check.Errors = append(check.Errors, "template is nil")

		return check
	}

	check.Name = tmpl.GetName()
	check.Kind = tmpl.Spec.CRD.Spec.Names.Kind

	if check.Kind == "" {
		check.Errors = append(check.Errors, "spec.crd.spec.names.kind is empty: the template does not define a constraint kind")
	}

	if len(tmpl.Spec.Targets) == 0 {
		check.Status = CheckFail
		check.Errors = append(check.Errors, "spec.targets is empty: the template defines no policy and every resource will be allowed")

		return check
	}

	var regoSources []string

	seenEngines := make(map[string]struct{})

	for _, target := range tmpl.Spec.Targets {
		if target.Rego != "" {
			regoSources = append(regoSources, target.Rego)

			if _, ok := seenEngines["Rego"]; !ok {
				seenEngines["Rego"] = struct{}{}
				check.Engines = append(check.Engines, "Rego")
			}
		}

		for _, code := range target.Code {
			engine := code.Engine
			if engine == "" {
				engine = "Unknown"
			}

			if _, ok := seenEngines[engine]; !ok {
				seenEngines[engine] = struct{}{}
				check.Engines = append(check.Engines, engine)
			}

			if strings.EqualFold(code.Engine, "rego") && code.Source != nil {
				if source, ok := code.Source.GetValue().(map[string]interface{}); ok {
					if rego, ok := source["rego"].(string); ok && rego != "" {
						regoSources = append(regoSources, rego)
					}
				}
			}
		}
	}

	if len(check.Engines) == 0 && len(regoSources) == 0 {
		check.Status = CheckFail
		check.Errors = append(check.Errors, "template contains no policy code (spec.targets[].rego or spec.targets[].code): it cannot produce violations and every resource will be allowed")

		return check
	}

	parsedAny := false
	violationRuleFound := false

	for _, source := range regoSources {
		module, err := parseRego(source)
		if err != nil {
			// Compilation through the constraint client reports the precise
			// error; do not guess here.
			continue
		}

		parsedAny = true

		if moduleHasViolationRule(module) {
			violationRuleFound = true
		}
	}

	check.HasViolationRule = violationRuleFound

	// Only fail on a missing violation rule when the Rego sources actually
	// parsed, otherwise the compile error below is the authoritative failure.
	if len(regoSources) > 0 && parsedAny && !violationRuleFound {
		check.Status = CheckFail
		check.Errors = append(check.Errors, "no \"violation\" rule found in Rego source: Gatekeeper only rejects resources through violation[...] rules, so this template compiles but silently allows every resource")
	}

	return check
}

func parseRego(source string) (*opaparser.Module, error) {
	module, err := opaparser.ParseModuleWithOpts("constrainttemplate.rego", source, opaparser.ParserOptions{
		RegoVersion: opaparser.RegoV1,
	})
	if err == nil {
		return module, nil
	}

	moduleV0, errV0 := opaparser.ParseModuleWithOpts("constrainttemplate.rego", source, opaparser.ParserOptions{
		RegoVersion: opaparser.RegoV0,
	})
	if errV0 != nil {
		return nil, err
	}

	return moduleV0, nil
}

func moduleHasViolationRule(module *opaparser.Module) bool {
	if module == nil {
		return false
	}

	for _, rule := range module.Rules {
		if rule == nil || rule.Head == nil {
			continue
		}

		if rule.Head.Name.String() == "violation" {
			return true
		}
	}

	return false
}
