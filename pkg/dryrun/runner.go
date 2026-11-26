package dryrun

import (
	"context"
	"fmt"
	"sort"

	constraintclient "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/rego"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/reviews"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/drivers/k8scel"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/target"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/util"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Option configures a [Runner].
type Option func(*config)

type config struct {
	templates        []*templates.ConstraintTemplate
	constraints      []*unstructured.Unstructured
	resources        []*unstructured.Unstructured
	data             []*unstructured.Unstructured
	enableCEL        bool
	enforcementPoint string
}

// WithTemplates appends ConstraintTemplates to the run.
func WithTemplates(templates ...*templates.ConstraintTemplate) Option {
	return func(c *config) {
		c.templates = append(c.templates, templates...)
	}
}

// WithConstraints appends Constraints to the run.
func WithConstraints(constraints ...*unstructured.Unstructured) Option {
	return func(c *config) {
		c.constraints = append(c.constraints, constraints...)
	}
}

// WithResources appends the resources to review.
func WithResources(resources ...*unstructured.Unstructured) Option {
	return func(c *config) {
		c.resources = append(c.resources, resources...)
	}
}

// WithInventory appends objects to load into the constraint cache as data,
// for referential policies.
func WithInventory(objects ...*unstructured.Unstructured) Option {
	return func(c *config) {
		c.data = append(c.data, objects...)
	}
}

// WithCEL enables the CEL (K8sNativeValidation) driver in addition to Rego.
// The CEL driver is enabled by default; pass false to [NewRunner] options via
// [WithoutCEL] when only Rego templates are used.
func WithCEL() Option {
	return func(c *config) {
		c.enableCEL = true
	}
}

// WithoutCEL disables the CEL driver.
func WithoutCEL() Option {
	return func(c *config) {
		c.enableCEL = false
	}
}

// WithEnforcementPoint overrides the enforcement point used to resolve scoped
// enforcement actions. It defaults to the gator enforcement point.
func WithEnforcementPoint(point string) Option {
	return func(c *config) {
		c.enforcementPoint = point
	}
}

// WithManifest wires every classified object of a [Manifest] into the runner.
func WithManifest(m *Manifest) Option {
	return func(c *config) {
		if m == nil {
			return
		}

		c.templates = append(c.templates, m.Templates...)
		c.constraints = append(c.constraints, m.Constraints...)
		c.resources = append(c.resources, m.Resources...)
	}
}

// Runner evaluates resources against a fixed set of templates and
// constraints. A Runner is safe for repeated DryRun/Enforce calls; evaluation
// never mutates Kubernetes state.
type Runner struct {
	cfg config

	client *constraintclient.Client

	checks           []TemplateCheck
	kindToTemplate   map[string]string
	constraintErrors []ReportError
	dataErrors       []ReportError
}

// NewRunner compiles the supplied templates and constraints in an isolated
// constraint-framework client. Template compilation problems are reported
// through [Runner.Checks] instead of aborting construction, so one broken
// template cannot hide the impact of the remaining policies.
func NewRunner(ctx context.Context, opts ...Option) (*Runner, error) {
	cfg := config{
		enableCEL:        true,
		enforcementPoint: util.GatorEnforcementPoint,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	client, err := newClient(&cfg)
	if err != nil {
		return nil, err
	}

	runner := &Runner{
		cfg:            cfg,
		client:         client,
		kindToTemplate: make(map[string]string),
	}

	for _, tmpl := range cfg.templates {
		check := inspectTemplate(tmpl)

		if _, addErr := client.AddTemplate(ctx, tmpl); addErr != nil {
			check.Status = CheckFail
			check.Errors = append(check.Errors, addErr.Error())
		}

		runner.checks = append(runner.checks, check)

		if kind := tmpl.Spec.CRD.Spec.Names.Kind; kind != "" {
			runner.kindToTemplate[kind] = tmpl.GetName()
		}
	}

	constraints := cfg.constraints

	// A template can be trial-run without explicitly authoring a
	// Constraint. When no constraints were supplied, synthesize an
	// all-matching constraint per template so the template's own behavior is
	// what gets exercised.
	if len(constraints) == 0 {
		for _, tmpl := range cfg.templates {
			name := tmpl.GetName()
			if name == "" {
				name = tmpl.Spec.CRD.Spec.Names.Kind
			}

			constraints = append(constraints, DefaultConstraint(tmpl, "trial-"+name, nil))
		}
	}

	for _, constraint := range constraints {
		if _, addErr := client.AddConstraint(ctx, constraint); addErr != nil {
			runner.constraintErrors = append(runner.constraintErrors, ReportError{
				Scope:   ScopeConstraint,
				Name:    constraint.GetName(),
				Message: addErr.Error(),
			})
		}
	}

	for _, obj := range cfg.data {
		if _, addErr := client.AddData(ctx, obj); addErr != nil {
			runner.dataErrors = append(runner.dataErrors, ReportError{
				Scope:   ScopeData,
				Name:    obj.GetName(),
				Message: addErr.Error(),
			})
		}
	}

	// gator loads reviewed objects as data as well, which makes referential
	// policies behave identically to `gator test`. Failures are non-fatal and
	// reported.
	for _, obj := range cfg.resources {
		if _, addErr := client.AddData(ctx, obj); addErr != nil {
			runner.dataErrors = append(runner.dataErrors, ReportError{
				Scope:   ScopeData,
				Name:    obj.GetName(),
				Message: addErr.Error(),
			})
		}
	}

	return runner, nil
}

func newClient(cfg *config) (*constraintclient.Client, error) {
	args := []constraintclient.Opt{
		constraintclient.Targets(&target.K8sValidationTarget{}),
		constraintclient.EnforcementPoints(cfg.enforcementPoint),
	}

	regoDriver, err := rego.New()
	if err != nil {
		return nil, fmt.Errorf("dryrun: creating Rego driver: %w", err)
	}

	args = append(args, constraintclient.Driver(regoDriver))

	if cfg.enableCEL {
		celDriver, celErr := k8scel.New()
		if celErr != nil {
			return nil, fmt.Errorf("dryrun: creating CEL driver: %w", celErr)
		}

		args = append(args, constraintclient.Driver(celDriver))
	}

	client, err := constraintclient.NewClient(args...)
	if err != nil {
		return nil, fmt.Errorf("dryrun: creating constraint client: %w", err)
	}

	return client, nil
}

// Checks returns the template self-check results gathered at construction.
func (r *Runner) Checks() []TemplateCheck {
	if r == nil {
		return nil
	}

	return r.checks
}

// DryRun evaluates resources and returns the impact report without blocking
// anything. When no resources are passed, the resources supplied through
// [WithResources] are used.
func (r *Runner) DryRun(ctx context.Context, resources ...*unstructured.Unstructured) (*Report, error) {
	report := r.evaluate(ctx, resources)
	report.Mode = ModeDryRun
	report.Allowed = true

	return report, nil
}

// Enforce evaluates resources and returns the admission decision. Allowed is
// false exactly when at least one resource carries a deny violation. The
// evaluation path is identical to [Runner.DryRun], so the denied set matches
// the dry-run prediction.
func (r *Runner) Enforce(ctx context.Context, resources ...*unstructured.Unstructured) (*Report, error) {
	report := r.evaluate(ctx, resources)
	report.Mode = ModeEnforce
	report.Allowed = len(report.DeniedResources) == 0

	return report, nil
}

func (r *Runner) evaluate(ctx context.Context, resources []*unstructured.Unstructured) *Report {
	if len(resources) == 0 {
		resources = r.cfg.resources
	}

	report := &Report{
		ResourceCount:  len(resources),
		TemplateChecks: r.checks,
		Errors:         append(append([]ReportError{}, r.constraintErrors...), r.dataErrors...),
	}

	deniedSeen := make(map[string]struct{})

	for _, obj := range resources {
		ref := RefOf(obj)
		resourceReport := ResourceReport{Resource: ref}

		augmented := target.AugmentedUnstructured{Object: *obj}

		responses, err := r.client.Review(ctx, augmented, reviews.EnforcementPoint(r.cfg.enforcementPoint))
		if err != nil {
			message := err.Error()
			resourceReport.ReviewError = message
			report.Errors = append(report.Errors, ReportError{
				Scope:    ScopeResource,
				Name:     obj.GetName(),
				Resource: &ref,
				Message:  message,
			})
			report.Resources = append(report.Resources, resourceReport)

			continue
		}

		for _, result := range responses.Results() {
			violation := r.toViolation(result, &ref)
			resourceReport.Violations = append(resourceReport.Violations, violation)
			report.Violations = append(report.Violations, violation)

			if violation.WouldDeny {
				resourceReport.WouldDeny = true
			}
		}

		resourceReport.Messages = sortedMessages(resourceReport.Violations)

		report.Resources = append(report.Resources, resourceReport)

		if len(resourceReport.Violations) > 0 {
			report.ViolatingResources = append(report.ViolatingResources, resourceReport)
		}

		if resourceReport.WouldDeny {
			key := ref.String()
			if _, ok := deniedSeen[key]; !ok {
				deniedSeen[key] = struct{}{}
				report.DeniedResources = append(report.DeniedResources, ref)
			}
		}
	}

	report.ViolationCount = len(report.Violations)

	return report
}

func (r *Runner) toViolation(result *types.Result, ref *ResourceRef) Violation {
	violation := Violation{
		Resource:                 *ref,
		Message:                  result.Msg,
		EnforcementAction:        result.EnforcementAction,
		ScopedEnforcementActions: result.ScopedEnforcementActions,
		WouldDeny:                denies(result.EnforcementAction, result.ScopedEnforcementActions),
	}

	if result.Constraint != nil {
		violation.Constraint = result.Constraint.GetName()
		violation.ConstraintKind = result.Constraint.GetKind()
		violation.Template = r.kindToTemplate[result.Constraint.GetKind()]
	}

	return violation
}

func sortedMessages(violations []Violation) []string {
	seen := make(map[string]struct{}, len(violations))

	var messages []string

	for i := range violations {
		message := violations[i].Message
		if message == "" {
			continue
		}

		if _, ok := seen[message]; ok {
			continue
		}

		seen[message] = struct{}{}
		messages = append(messages, message)
	}

	sort.Strings(messages)

	return messages
}
