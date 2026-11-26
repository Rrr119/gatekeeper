package dryrun

import (
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Mode determines whether a run only reports violations or also rejects
// resources that produce deny violations.
type Mode string

const (
	// ModeDryRun evaluates policies and lists would-be rejected resources
	// without blocking anything.
	ModeDryRun Mode = "dryrun"

	// ModeEnforce evaluates policies and denies resources that violate a
	// constraint whose enforcement action resolves to "deny".
	ModeEnforce Mode = "enforce"
)

// Enforcement actions understood by this package. They mirror
// github.com/open-policy-agent/gatekeeper/v3/pkg/util.EnforcementAction and
// are duplicated here to keep the dry-run API self-contained.
const (
	// ActionDeny rejects the request when a violation is present.
	ActionDeny = "deny"

	// ActionDryrun records violations but never blocks admission.
	ActionDryrun = "dryrun"

	// ActionWarn surfaces a warning but allows admission.
	ActionWarn = "warn"

	// ActionScoped defers the decision to ScopedEnforcementActions.
	ActionScoped = "scoped"
)

// ResourceRef identifies a Kubernetes resource affected by a policy decision.
type ResourceRef struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Group      string `json:"group,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
}

// RefOf builds a [ResourceRef] from an unstructured resource.
func RefOf(obj *unstructured.Unstructured) ResourceRef {
	if obj == nil {
		return ResourceRef{}
	}

	gvk := obj.GroupVersionKind()

	return ResourceRef{
		APIVersion: obj.GetAPIVersion(),
		Group:      gvk.Group,
		Kind:       gvk.Kind,
		Namespace:  obj.GetNamespace(),
		Name:       obj.GetName(),
	}
}

// String renders the resource similarly to kubectl resource names.
func (r ResourceRef) String() string {
	group := r.Group
	if group == "" && strings.Contains(r.APIVersion, "/") {
		group, _, _ = strings.Cut(r.APIVersion, "/")
	}

	kind := r.Kind
	if group != "" {
		kind = group + "/" + kind
	}

	if r.Namespace != "" {
		return fmt.Sprintf("%s %s/%s", kind, r.Namespace, r.Name)
	}

	return fmt.Sprintf("%s %s", kind, r.Name)
}

// Violation is a single constraint decision against a resource.
type Violation struct {
	// Resource is the reviewed resource.
	Resource ResourceRef `json:"resource"`

	// Template is the name of the ConstraintTemplate that owns the constraint.
	Template string `json:"template,omitempty"`

	// ConstraintKind and Constraint identify the violating constraint.
	ConstraintKind string `json:"constraintKind,omitempty"`
	Constraint     string `json:"constraint,omitempty"`

	// Message is the policy-provided violation message.
	Message string `json:"message,omitempty"`

	// EnforcementAction is the resolved enforcement action of the constraint.
	EnforcementAction string `json:"enforcementAction,omitempty"`

	// ScopedEnforcementActions lists enforcement actions scoped to enforcement
	// points, when the constraint uses scoped enforcement actions.
	ScopedEnforcementActions []string `json:"scopedEnforcementActions,omitempty"`

	// WouldDeny is true when this violation rejects the resource under
	// enforcement ("deny" action, including scoped deny).
	WouldDeny bool `json:"wouldDeny"`
}

// ResourceReport collects all violations produced for one resource.
type ResourceReport struct {
	// Resource identifies the reviewed resource.
	Resource ResourceRef `json:"resource"`

	// Violations are all constraint violations for the resource.
	Violations []Violation `json:"violations,omitempty"`

	// Messages is a de-duplicated, sorted view of violation messages.
	Messages []string `json:"messages,omitempty"`

	// WouldDeny is true when at least one violation rejects the resource.
	WouldDeny bool `json:"wouldDeny"`

	// ReviewError captures an evaluation error for this resource. Evaluation
	// errors never abort the whole run so that the full impact list is
	// produced.
	ReviewError string `json:"reviewError,omitempty"`
}

// ReportError describes a non-policy failure while loading or evaluating.
type ReportError struct {
	// Scope is one of "template", "constraint", or "resource".
	Scope string `json:"scope"`

	// Name names the affected object when known.
	Name string `json:"name,omitempty"`

	// Resource identifies the affected resource for scope "resource".
	Resource *ResourceRef `json:"resource,omitempty"`

	// Message is the failure description.
	Message string `json:"message"`
}

// Report is the outcome of a dry-run or enforcement run.
type Report struct {
	// Mode is the run mode.
	Mode Mode `json:"mode"`

	// ResourceCount is the number of resources reviewed.
	ResourceCount int `json:"resourceCount"`

	// ViolationCount is the total number of constraint violations.
	ViolationCount int `json:"violationCount"`

	// Violations is the flat list of all violations.
	Violations []Violation `json:"violations,omitempty"`

	// Resources contains one report per reviewed resource, in input order.
	Resources []ResourceReport `json:"resources,omitempty"`

	// ViolatingResources is the "violation resource list": only resources
	// with at least one violation.
	ViolatingResources []ResourceReport `json:"violatingResources,omitempty"`

	// DeniedResources lists the resources that would be (dry-run) or are
	// (enforce) rejected. DryRun never blocks, so use this field to predict
	// enforcement behavior.
	DeniedResources []ResourceRef `json:"deniedResources,omitempty"`

	// Allowed is the actual admission decision of the run. It is always true
	// in [ModeDryRun]; in [ModeEnforce] it equals len(DeniedResources) == 0.
	Allowed bool `json:"allowed"`

	// TemplateChecks are the self-check results for the loaded templates.
	TemplateChecks []TemplateCheck `json:"templateChecks,omitempty"`

	// Errors collects constraint/resource evaluation failures that did not
	// prevent the run from completing.
	Errors []ReportError `json:"errors,omitempty"`
}

// DeniedRefs returns the denied resource references as a sorted, de-duplicated
// list. It is useful for comparing dry-run and enforce reports.
func (r *Report) DeniedRefs() []string {
	if r == nil {
		return nil
	}

	seen := make(map[string]struct{}, len(r.DeniedResources))
	out := make([]string, 0, len(r.DeniedResources))

	for _, ref := range r.DeniedResources {
		key := ref.String()
		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = struct{}{}
		out = append(out, key)
	}

	sort.Strings(out)

	return out
}

// ViolatingRefs returns all resources carrying at least one violation as a
// sorted, de-duplicated list.
func (r *Report) ViolatingRefs() []string {
	if r == nil {
		return nil
	}

	seen := make(map[string]struct{}, len(r.ViolatingResources))
	out := make([]string, 0, len(r.ViolatingResources))

	for i := range r.ViolatingResources {
		key := r.ViolatingResources[i].Resource.String()
		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = struct{}{}
		out = append(out, key)
	}

	sort.Strings(out)

	return out
}

// denies reports whether an enforcement action rejects admission. An empty
// action is treated as "deny" because deny is the framework default.
func denies(action string, scopedActions []string) bool {
	switch action {
	case ActionDeny, "":
		return true
	case ActionScoped:
		for _, a := range scopedActions {
			if a == ActionDeny {
				return true
			}
		}

		return false
	default:
		return false
	}
}
