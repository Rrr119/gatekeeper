// Package dryrun provides ConstraintTemplate self-checks and policy impact
// analysis ("dry-run") for Gatekeeper.
//
// A malformed ConstraintTemplate can compile yet silently match nothing, in
// which case Gatekeeper admits every resource and operators may never notice.
// This package catches such templates with [CheckTemplate] and predicts the
// admission impact of a policy set with [Runner.DryRun].
//
// Dry-run and enforcement share the same constraint-framework evaluation path
// ([Runner.evaluate]); they differ only in whether deny violations are turned
// into an admission rejection. This guarantees that the resources listed as
// denied by a dry-run are exactly the resources rejected by [Runner.Enforce]
// and by Gatekeeper's validating admission webhook once the policy is live.
//
// Existing ConstraintTemplate and Constraint manifests are supported directly;
// no new CRD or manifest field is required.
package dryrun
