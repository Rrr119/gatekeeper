# ConstraintTemplate self-check and dry-run

A typo in a ConstraintTemplate can make its `violation` rule never fire.
Gatekeeper then compiles the template (or reports a status error nobody
reads) and admits every resource: the cluster fails open silently.

The `pkg/dryrun` package and the `gator dryrun` command close that gap.

## What it provides

- **Template self-check** (`dryrun.CheckTemplate` / `gator dryrun --check-only`):
  verifies the template structure, compiles it with the same constraint
  framework Gatekeeper uses, checks that a Rego `violation[...]` rule actually
  exists, and optionally runs behavioral probes that prove a known-bad
  resource is rejected.
- **Dry-run mode** (`Runner.DryRun` / `gator dryrun`): evaluates resources
  against existing ConstraintTemplates and Constraints and produces the
  **violation resource list** (`Report.ViolatingResources`) and the predicted
  deny list (`Report.DeniedResources`) without blocking anything.
- **Enforce parity** (`Runner.Enforce` / `gator dryrun --enforce`): uses the
  exact same evaluation path and only changes the admission decision, so the
  resources denied after rollout match the dry-run list one-to-one.
- **Compatibility**: no new CRD fields are required. `templates.gatekeeper.sh/v1`
  and `v1beta1` ConstraintTemplates and ordinary Constraints are parsed as-is.

## Acceptance scenario: 3 templates

`acceptance.yaml` contains exactly three templates
(`K8sRequiredLabels`, `K8sDisallowLatest`, `K8sAllowedRegistries`), their
constraints and five resources. Three resources violate policy.

```bash
# Dry run: lists the three would-be rejected resources, exits 0, blocks nothing.
go run ./cmd/gator dryrun -f demo/dryrun/acceptance.yaml

# Simulate go-live: same three resources are denied, exit code 1.
go run ./cmd/gator dryrun -f demo/dryrun/acceptance.yaml --enforce

# Machine-readable report.
go run ./cmd/gator dryrun -f demo/dryrun/acceptance.yaml -o json
```

`broken-template.yaml` is a template whose rule is misspelled `violations`;
it compiles but would silently allow everything. The self-check fails it:

```bash
go run ./cmd/gator dryrun -f demo/dryrun/broken-template.yaml --check-only
# exit code 2
```

The same scenario is asserted in code:

```bash
go test ./pkg/dryrun/... -run TestAcceptance -v
go test ./cmd/gator/dryrun/... -v
```

Constraints that already set `spec.enforcementAction: dryrun` are honored:
their violations appear in the list with `wouldDeny: false`, so even
`gator dryrun --enforce` predicts they stay non-blocking until the action is
changed to `deny`.
