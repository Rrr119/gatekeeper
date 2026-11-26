// Package dryrun implements the `gator dryrun` subcommand.
package dryrun

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	cmdutils "github.com/open-policy-agent/gatekeeper/v3/cmd/gator/util"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/dryrun"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/gator/reader"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

const examples = `# Dry-run a manifest: list the resources policies would reject, without blocking
gator dryrun --filename="manifest.yaml"

# Dry-run a directory of templates, constraints and resources
gator dryrun --filename="policies-and-resources/"

# Run template self-checks only (exits non-zero if a template is broken)
gator dryrun --filename="templates/" --check-only

# Simulate going live: exits 1 when any resource would be denied
gator dryrun --filename="manifest.yaml" --enforce

# Emit the full dry-run report as JSON
gator dryrun --filename="manifest.yaml" --output=json`

// Cmd is the `gator dryrun` cobra command.
var Cmd = &cobra.Command{
	Use:     "dryrun",
	Short:   "self-check ConstraintTemplates and dry-run policies against resources, listing would-be rejected objects without blocking.",
	Example: examples,
	Args:    cobra.NoArgs,
	Run:     run,
}

const (
	outputJSON  = "json"
	outputYAML  = "yaml"
	outputHuman = "default"

	exitOK          = 0
	exitDenied      = 1
	exitCheckFailed = 2
	fourSpaceIndent = "    "
)

var (
	flagFilenames   []string
	flagOutput      string
	flagEnforce     bool
	flagCheckOnly   bool
	flagStrictCheck bool
)

func init() {
	Cmd.Flags().StringArrayVarP(&flagFilenames, "filename", "f", []string{}, "a file or directory containing ConstraintTemplates, Constraints and Kubernetes resources. Can be specified multiple times.")
	Cmd.Flags().StringVarP(&flagOutput, "output", "o", "", fmt.Sprintf("Output format. One of: %s|%s.", outputJSON, outputYAML))
	Cmd.Flags().BoolVar(&flagEnforce, "enforce", false, "simulate live enforcement instead of dry-run mode; exits 1 when resources would be denied.")
	Cmd.Flags().BoolVar(&flagCheckOnly, "check-only", false, "only run ConstraintTemplate self-checks; exits 2 when a template fails the check.")
	Cmd.Flags().BoolVar(&flagStrictCheck, "strict-check", false, "make failed template self-checks exit 2 even during a dry run.")
}

func run(_ *cobra.Command, _ []string) {
	exitCode, err := Execute(os.Stdout, flagFilenames, flagOutput, Options{
		Enforce:     flagEnforce,
		CheckOnly:   flagCheckOnly,
		StrictCheck: flagStrictCheck,
	})
	if err != nil {
		cmdutils.ErrFatalf("%v", err)
	}

	os.Exit(exitCode)
}

// Options controls the non-output behavior of [Execute].
type Options struct {
	// Enforce simulates the live admission decision.
	Enforce bool

	// CheckOnly only reports template self-checks.
	CheckOnly bool

	// StrictCheck makes failed self-checks return exit code 2.
	StrictCheck bool
}

// Execute runs the dry-run command with explicit arguments and writes output
// to w. It returns the process exit code: 0 on success, 1 when enforcement
// would deny resources, and 2 when strict/check-only self-checks fail.
func Execute(w io.Writer, filenames []string, output string, opts Options) (int, error) {
	objects, err := reader.ReadSources(filenames, nil, "", false)
	if err != nil {
		return exitOK, fmt.Errorf("reading input: %w", err)
	}

	if len(objects) == 0 {
		return exitOK, fmt.Errorf("no input data identified; pass manifests with --filename or stdin")
	}

	manifest, err := dryrun.Classify(objects...)
	if err != nil {
		return exitOK, err
	}

	ctx := context.Background()

	runner, err := dryrun.NewRunner(ctx, dryrun.WithManifest(manifest))
	if err != nil {
		return exitOK, err
	}

	checks := runner.Checks()
	checksFailed := failedChecks(checks)

	if opts.CheckOnly {
		if err := writeChecks(w, output, checks, nil); err != nil {
			return exitOK, err
		}

		if checksFailed {
			return exitCheckFailed, nil
		}

		return exitOK, nil
	}

	var report *dryrun.Report
	if opts.Enforce {
		report, err = runner.Enforce(ctx)
	} else {
		report, err = runner.DryRun(ctx)
	}

	if err != nil {
		return exitOK, err
	}

	report.TemplateChecks = checks

	if err := writeReport(w, output, report); err != nil {
		return exitOK, err
	}

	switch {
	case checksFailed && (opts.StrictCheck || opts.CheckOnly):
		return exitCheckFailed, nil
	case opts.Enforce && len(report.DeniedResources) > 0:
		return exitDenied, nil
	default:
		// Dry-run never blocks on violations.
		return exitOK, nil
	}
}

func failedChecks(checks []dryrun.TemplateCheck) bool {
	for i := range checks {
		if !checks[i].OK() {
			return true
		}
	}

	return false
}

func writeChecks(w io.Writer, format string, checks []dryrun.TemplateCheck, report *dryrun.Report) error {
	if format == outputJSON || format == outputYAML {
		payload := map[string]interface{}{"templateChecks": checks}
		if report != nil {
			payload["report"] = report
		}

		return writeStructured(w, format, payload)
	}

	fmt.Fprintf(w, "Template self-check: %d template(s)\n", len(checks))

	for i := range checks {
		check := &checks[i]
		status := "PASS"
		if !check.OK() {
			status = "FAIL"
		}

		fmt.Fprintf(w, "  [%s] %s (kind=%s)\n", status, check.Name, check.Kind)

		for _, problem := range check.Errors {
			fmt.Fprintf(w, "      error: %s\n", problem)
		}

		for _, warning := range check.Warnings {
			fmt.Fprintf(w, "      warning: %s\n", warning)
		}
	}

	return nil
}

func writeReport(w io.Writer, format string, report *dryrun.Report) error {
	switch strings.ToLower(format) {
	case outputJSON:
		encoded, err := json.MarshalIndent(report, "", fourSpaceIndent)
		if err != nil {
			return fmt.Errorf("marshaling JSON report: %w", err)
		}

		_, err = fmt.Fprintln(w, string(encoded))

		return err
	case outputYAML:
		return writeStructured(w, outputYAML, report)
	case "", outputHuman:
		return writeHumanReport(w, report)
	default:
		return fmt.Errorf("unsupported output format %q (expected json or yaml)", format)
	}
}

func writeStructured(w io.Writer, format string, payload interface{}) error {
	switch strings.ToLower(format) {
	case outputJSON:
		encoded, err := json.MarshalIndent(payload, "", fourSpaceIndent)
		if err != nil {
			return fmt.Errorf("marshaling JSON: %w", err)
		}

		_, err = fmt.Fprintln(w, string(encoded))

		return err
	case outputYAML:
		// Round-trip through JSON so the struct json tags drive YAML keys.
		encoded, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("pre-marshaling YAML: %w", err)
		}

		var generic interface{}
		if err := json.Unmarshal(encoded, &generic); err != nil {
			return fmt.Errorf("pre-unmarshaling YAML: %w", err)
		}

		yamlBytes, err := yaml.Marshal(generic)
		if err != nil {
			return fmt.Errorf("marshaling YAML: %w", err)
		}

		_, err = w.Write(yamlBytes)

		return err
	default:
		return fmt.Errorf("unsupported structured output format %q", format)
	}
}

func writeHumanReport(w io.Writer, report *dryrun.Report) error {
	if err := writeChecks(w, outputHuman, report.TemplateChecks, nil); err != nil {
		return err
	}

	mode := "DRY RUN (admission not blocked)"
	if report.Mode == dryrun.ModeEnforce {
		mode = "ENFORCE (live decision)"
	}

	fmt.Fprintf(w, "\nMode: %s\n", mode)
	fmt.Fprintf(w, "Reviewed %d resource(s); %d violation(s) on %d resource(s); %d resource(s) would be denied.\n",
		report.ResourceCount, report.ViolationCount, len(report.ViolatingResources), len(report.DeniedResources))

	if len(report.ViolatingResources) == 0 {
		fmt.Fprintln(w, "\nNo violating resources found.")
	} else {
		fmt.Fprintln(w, "\nViolation resource list:")

		for i := range report.ViolatingResources {
			resourceReport := &report.ViolatingResources[i]
			denyMarker := ""
			if resourceReport.WouldDeny {
				denyMarker = " [WOULD DENY]"
			}

			fmt.Fprintf(w, "  %s%s\n", slashName(&resourceReport.Resource), denyMarker)

			for _, message := range resourceReport.Messages {
				fmt.Fprintf(w, "      - %s\n", message)
			}
		}
	}

	if len(report.Errors) > 0 {
		fmt.Fprintln(w, "\nEvaluation errors:")

		for _, evalErr := range report.Errors {
			fmt.Fprintf(w, "  [%s] %s: %s\n", evalErr.Scope, evalErr.Name, evalErr.Message)
		}
	}

	switch {
	case report.Mode == dryrun.ModeDryRun:
		fmt.Fprintln(w, "\nDry run does not block any request; re-run with --enforce to simulate the live webhook decision.")
	case report.Allowed:
		fmt.Fprintln(w, "\nEnforcement decision: ALLOW.")
	default:
		fmt.Fprintln(w, "\nEnforcement decision: DENY for the resources marked [WOULD DENY].")
	}

	return nil
}

func slashName(ref *dryrun.ResourceRef) string {
	switch {
	case ref.Namespace != "":
		return fmt.Sprintf("%s/%s/%s", ref.Kind, ref.Namespace, ref.Name)
	case ref.Kind != "":
		return fmt.Sprintf("%s/%s", ref.Kind, ref.Name)
	default:
		return ref.Name
	}
}
