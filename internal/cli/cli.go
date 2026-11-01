package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ipsofacto-io/ipso/internal/baseline"
	"github.com/ipsofacto-io/ipso/internal/bundle"
	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/archunit"
	"github.com/ipsofacto-io/ipso/internal/compiler/builtin"
	"github.com/ipsofacto-io/ipso/internal/compiler/checkov"
	"github.com/ipsofacto-io/ipso/internal/compiler/cibinding"
	"github.com/ipsofacto-io/ipso/internal/compiler/depcruise"
	"github.com/ipsofacto-io/ipso/internal/compiler/eslint"
	"github.com/ipsofacto-io/ipso/internal/compiler/gatekeeper"
	"github.com/ipsofacto-io/ipso/internal/compiler/importlinter"
	"github.com/ipsofacto-io/ipso/internal/compiler/kyverno"
	"github.com/ipsofacto-io/ipso/internal/compiler/opa"
	"github.com/ipsofacto-io/ipso/internal/compiler/semgrep"
	"github.com/ipsofacto-io/ipso/internal/compiler/toolrun"
	"github.com/ipsofacto-io/ipso/internal/config"
	"github.com/ipsofacto-io/ipso/internal/edr"
	"github.com/ipsofacto-io/ipso/internal/premise"
	"github.com/ipsofacto-io/ipso/internal/sarif"
)

// deps is the clock, compiler registry, and premise client for one invocation.
// Tests inject them. The binary uses the local clock, the built-in registry,
// and a premise client that dials only a public address.
type deps struct {
	now         func() time.Time
	registry    compiler.Registry
	probeClient premise.Client
	// capture collects raw outcomes for ipso baseline. Set, it also stops the stamped baseline from applying.
	capture *capturedChecks
}

// Run executes one CLI invocation. args excludes the program name.
func Run(args []string, stdout, stderr io.Writer) int {
	return run(args, stdout, stderr, deps{now: time.Now, registry: builtin.Registry()})
}

func run(args []string, stdout, stderr io.Writer, d deps) int {
	if len(args) == 0 {
		fprintln(stderr, usage)
		return 2
	}
	root, err := os.Getwd()
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	switch args[0] {
	case "init":
		if len(args) != 1 {
			fprintln(stderr, "usage: ipso init")
			return 2
		}
		return initCmd(root, stdout, stderr)
	case "check":
		return checkCmd(root, args[1:], stdout, stderr, d)
	case "explain":
		if len(args) != 2 || args[1] == "" {
			fprintln(stderr, "usage: ipso explain <slug>")
			return 2
		}
		return explainCmd(root, args[1], stdout, stderr)
	case "import":
		if len(args) > 1 && args[1] == "" {
			fprintln(stderr, "usage: ipso import [path...]")
			return 2
		}
		return importCmd(root, args[1:], stdout, stderr)
	case "compile":
		if len(args) != 1 {
			fprintln(stderr, "usage: ipso compile")
			return 2
		}
		return compileCmd(root, stdout, stderr, d)
	case "bundle":
		return bundleCmd(root, args[1:], stdout, stderr)
	case "premise":
		return premiseCmd(root, args[1:], stdout, stderr, d)
	case "baseline":
		return baselineCmd(root, args[1:], stdout, stderr, d)
	case "-h", "--help", "help", "version", "--version", "-v":
		fprintln(stdout, helpText())
		return 0
	default:
		fprintf(stderr, "unknown command %q\n%s\n", args[0], usage)
		return 2
	}
}

// Version, Commit, and Date are set with -X at release time.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func helpText() string {
	return fmt.Sprintf("ipso %s (%s, %s)\n\n%s", Version, Commit, Date, usage)
}

const usage = `ipso reads and compiles engineering decision records in a repository.

usage:
  ipso init
  ipso check
  ipso check plan <plan.json|-> [--env name] [--input name] [--report file] [--sarif file] [--bundle dir --digest sha256:hex --key public.pem]
  ipso check ci <evidence.json|-> --sha <sha> [--env name] [--report file] [--sarif file]
  ipso check checkov <results.json|-> [--env name] [--input name] [--report file] [--sarif file]
  ipso check pulumi <preview.json|-> [--env name] [--input name] [--report file] [--sarif file]
  ipso check cloudformation <template|-> [--env name] [--input name] [--report file] [--sarif file]
  ipso check arm <template.json|-> [--env name] [--input name] [--report file] [--sarif file]
  ipso check depcruise <path>... [--env name] [--input name] [--report file] [--sarif file]
  ipso check semgrep <path>... [--env name] [--input name] [--report file] [--sarif file]
  ipso check archunit <classes-dir>... --jars <dir> [--env name] [--input name] [--report file] [--sarif file]
  ipso check importlinter <source-dir>... [--env name] [--input name] [--report file] [--sarif file]
  ipso check kyverno <path>... [--env name] [--input name] [--report file] [--sarif file]
  ipso check gatekeeper <path>... [--env name] [--input name] [--report file] [--sarif file]
  ipso check eslint <path>... [--env name] [--input name] [--report file] [--sarif file]
  ipso explain <slug>
  ipso import [path...]
  ipso premise check [--report file]
  ipso baseline create|update <subcommand> <args>
  ipso bundle pack --layout dir
  ipso bundle sign --layout dir --key private.pem
  ipso bundle verify --layout dir --digest sha256:hex --key public.pem
  ipso compile`

func initCmd(root string, stdout, stderr io.Writer) int {
	created, err := config.Init(root)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	path := config.Path(root)
	if created {
		fprintf(stdout, "wrote %s\n", displayPath(root, path))
		return 0
	}
	fprintf(stdout, "%s already exists\n", displayPath(root, path))
	return 0
}

func checkCmd(root string, args []string, stdout, stderr io.Writer, d deps) int {
	if len(args) == 0 {
		return checkFiles(root, stdout, stderr)
	}
	switch args[0] {
	case "plan":
		return planCmd(root, args[1:], stdout, stderr, d)
	case "ci":
		return ciCmd(root, args[1:], stdout, stderr, d)
	case "checkov":
		return checkovCmd(root, args[1:], stdout, stderr, d)
	case "pulumi":
		return adapterCmd(root, args[1:], pulumiCheck, stdout, stderr, d)
	case "cloudformation":
		return adapterCmd(root, args[1:], cloudformationCheck, stdout, stderr, d)
	case "arm":
		return adapterCmd(root, args[1:], armCheck, stdout, stderr, d)
	case "depcruise":
		return depcruiseCmd(root, args[1:], stdout, stderr, d)
	case "semgrep":
		return semgrepCmd(root, args[1:], stdout, stderr, d)
	case "archunit":
		return archunitCmd(root, args[1:], stdout, stderr, d)
	case "importlinter":
		return importlinterCmd(root, args[1:], stdout, stderr, d)
	case "kyverno":
		return kyvernoCmd(root, args[1:], stdout, stderr, d)
	case "gatekeeper":
		return gatekeeperCmd(root, args[1:], stdout, stderr, d)
	case "eslint":
		return eslintCmd(root, args[1:], stdout, stderr, d)
	default:
		fprintln(stderr, checkUsage)
		return 2
	}
}

func checkFiles(root string, stdout, stderr io.Writer) int {
	cfg, _, err := config.Load(root)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	files, err := edr.Match(root, cfg.Decisions)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	if len(files) == 0 {
		fprintln(stdout, "no EDR files found")
		return 0
	}
	failed := false
	for _, path := range files {
		shown := displayPath(root, path)
		doc, err := edr.ReadFile(path)
		if err != nil {
			fprintf(stdout, "%s: %s\n", shown, err)
			failed = true
			continue
		}
		problems := edr.Validate(doc)
		if len(problems) == 0 {
			fprintf(stdout, "%s: ok\n", shown)
			continue
		}
		failed = true
		for _, problem := range problems {
			fprintf(stdout, "%s: %s\n", shown, problem)
		}
	}
	if failed {
		return 1
	}
	return 0
}

const (
	planUsage         = "usage: ipso check plan <plan.json|-> [--env name] [--input name] [--report file] [--sarif file] [--bundle dir --digest sha256:hex --key public.pem]"
	ciUsage           = "usage: ipso check ci <evidence.json|-> --sha <sha> [--env name] [--report file] [--sarif file]"
	checkovUsage      = "usage: ipso check checkov <results.json|-> [--env name] [--input name] [--report file] [--sarif file]"
	depcruiseUsage    = "usage: ipso check depcruise <path>... [--env name] [--input name] [--report file] [--sarif file]"
	semgrepUsage      = "usage: ipso check semgrep <path>... [--env name] [--input name] [--report file] [--sarif file]"
	archunitUsage     = "usage: ipso check archunit <classes-dir>... --jars <dir> [--env name] [--input name] [--report file] [--sarif file]"
	importlinterUsage = "usage: ipso check importlinter <source-dir>... [--env name] [--input name] [--report file] [--sarif file]"
	kyvernoUsage      = "usage: ipso check kyverno <path>... [--env name] [--input name] [--report file] [--sarif file]"
	gatekeeperUsage   = "usage: ipso check gatekeeper <path>... [--env name] [--input name] [--report file] [--sarif file]"
	eslintUsage       = "usage: ipso check eslint <path>... [--env name] [--input name] [--report file] [--sarif file]"
	checkUsage        = planUsage + "\n" + ciUsage + "\n" + checkovUsage + "\n" + pulumiUsage + "\n" + cloudformationUsage + "\n" + armUsage + "\n" + depcruiseUsage + "\n" + semgrepUsage + "\n" + archunitUsage + "\n" + importlinterUsage + "\n" + kyvernoUsage + "\n" + gatekeeperUsage + "\n" + eslintUsage
)

func planCmd(root string, args []string, stdout, stderr io.Writer, d deps) int {
	opts, err := parsePlanArgs(args)
	if err != nil {
		fprintln(stderr, err)
		return 2
	}
	if d.now == nil {
		d.now = time.Now
	}
	var reader io.Reader
	if opts.path == "-" {
		reader = os.Stdin
	} else {
		file, err := os.Open(opts.path)
		if err != nil {
			fprintln(stderr, err)
			return 1
		}
		defer func() { _ = file.Close() }()
		reader = file
	}
	plan, err := opa.ReadPlan(reader)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	var build compiler.Build
	if opts.bundle != "" {
		build, err = bundle.Verify(opts.bundle, opts.digest, opts.key)
	} else {
		build, err = compiler.LoadBuild(root)
	}
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	now := d.now()
	report := compiler.PlanReport{
		ReportVersion: compiler.ReportVersion,
		IpsoVersion:   Version,
		EvaluatedAt:   now.UTC(),
		Env:           opts.env,
		PlanSHA256:    plan.SHA256(),
		BuildSHA256:   build.SHA256(),
	}
	verdicts, checks, failed, selected, err := evaluateChecks(d, baseline.Scope{Env: opts.env, Input: opts.input}, stdout, build, func(entry compiler.Entry) bool {
		return entry.Selected(opts.env, now)
	}, func(entry compiler.Entry, artifacts map[string][]byte) compiler.Outcome {
		return opa.EvalCheck(entry, artifacts, plan, now)
	})
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	report.Verdicts = verdicts
	if selected == 0 {
		fprintln(stdout, "no checks selected")
	}
	if err := writeOutputs(opts.report, opts.sarif, sarif.Category("plan", opts.env, opts.input), checks, func() ([]byte, error) {
		return compiler.MarshalReport(report)
	}); err != nil {
		fprintln(stderr, err)
		return 1
	}
	if failed {
		return 1
	}
	return 0
}

func ciCmd(root string, args []string, stdout, stderr io.Writer, d deps) int {
	opts, err := parseBoundArgs(args, ciUsage, true)
	if err != nil {
		fprintln(stderr, err)
		return 2
	}
	if !cibinding.ValidCommitSHA(opts.sha) {
		fprintln(stderr, ciUsage)
		return 2
	}
	if d.now == nil {
		d.now = time.Now
	}
	reader, err := openInput(opts.path)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	defer func() { _ = reader.Close() }()
	evidence, err := cibinding.ReadEvidence(reader, opts.sha)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	build, err := compiler.LoadBuild(root)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	now := d.now()
	verdicts, checks, failed, selected, err := evaluateChecks(d, baseline.Scope{Env: opts.env, Input: opts.input}, stdout, build, func(entry compiler.Entry) bool {
		return entry.Engine == "ci-binding" && entry.Applies(opts.env, now)
	}, func(entry compiler.Entry, artifacts map[string][]byte) compiler.Outcome {
		return cibinding.EvalCheck(entry, artifacts, evidence, now)
	})
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	if selected == 0 {
		fprintln(stdout, "no checks selected")
	}
	report := compiler.CIReport{
		ReportVersion:  compiler.ReportVersion,
		IpsoVersion:    Version,
		EvaluatedAt:    now.UTC(),
		Env:            opts.env,
		CommitSHA:      opts.sha,
		EvidenceSHA256: evidence.SHA256(),
		BuildSHA256:    build.SHA256(),
		Verdicts:       verdicts,
	}
	if err := writeOutputs(opts.report, opts.sarif, sarif.Category("ci", opts.env, opts.input), checks, func() ([]byte, error) {
		return compiler.MarshalCIReport(report)
	}); err != nil {
		fprintln(stderr, err)
		return 1
	}
	if failed {
		return 1
	}
	return 0
}

func checkovCmd(root string, args []string, stdout, stderr io.Writer, d deps) int {
	opts, err := parseBoundArgs(args, checkovUsage, false)
	if err != nil {
		fprintln(stderr, err)
		return 2
	}
	if d.now == nil {
		d.now = time.Now
	}
	reader, err := openInput(opts.path)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	defer func() { _ = reader.Close() }()
	results, err := checkov.ReadResults(reader)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	build, err := compiler.LoadBuild(root)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	now := d.now()
	verdicts, checks, failed, selected, err := evaluateChecks(d, baseline.Scope{Env: opts.env, Input: opts.input}, stdout, build, func(entry compiler.Entry) bool {
		return entry.Engine == "checkov" && entry.Applies(opts.env, now)
	}, func(entry compiler.Entry, artifacts map[string][]byte) compiler.Outcome {
		return checkov.EvalCheck(entry, artifacts, results, now)
	})
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	if selected == 0 {
		fprintln(stdout, "no checks selected")
	}
	report := compiler.CheckovReport{
		ReportVersion:  compiler.ReportVersion,
		IpsoVersion:    Version,
		EvaluatedAt:    now.UTC(),
		Env:            opts.env,
		EvidenceSHA256: results.SHA256(),
		BuildSHA256:    build.SHA256(),
		Verdicts:       verdicts,
	}
	if err := writeOutputs(opts.report, opts.sarif, sarif.Category("checkov", opts.env, opts.input), checks, func() ([]byte, error) {
		return compiler.MarshalCheckovReport(report)
	}); err != nil {
		fprintln(stderr, err)
		return 1
	}
	if failed {
		return 1
	}
	return 0
}

func semgrepCmd(root string, args []string, stdout, stderr io.Writer, d deps) int {
	opts, err := parsePathArgs(args, semgrepUsage, false)
	if err != nil {
		fprintln(stderr, err)
		return 2
	}
	if d.now == nil {
		d.now = time.Now
	}
	build, err := compiler.LoadBuild(root)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	now := d.now()
	selectedCount := 0
	for _, entry := range build.Entries {
		if entry.Engine == "semgrep" && entry.Applies(opts.env, now) {
			selectedCount++
		}
	}
	var tool semgrep.Tool
	var toolErr error
	if selectedCount > 0 {
		tool, toolErr = semgrep.FindTool(context.Background())
	}
	memo := semgrep.Memo{Tool: tool, Root: root, Paths: opts.paths}
	verdicts, checks, failed, selected, err := evaluateChecks(d, baseline.Scope{Env: opts.env, Input: opts.input}, stdout, build, func(entry compiler.Entry) bool {
		return entry.Engine == "semgrep" && entry.Applies(opts.env, now)
	}, func(entry compiler.Entry, artifacts map[string][]byte) compiler.Outcome {
		if toolErr != nil {
			return compiler.Outcome{Err: toolErr}
		}
		if tool.Version != entry.CompilerVersion {
			return compiler.Outcome{Err: &compiler.Error{Code: semgrep.CodeVersion, Err: fmt.Errorf("semgrep %s is not %s", tool.Version, entry.CompilerVersion)}}
		}
		config, ok := artifacts[semgrep.ArtifactName]
		if !ok {
			return compiler.Outcome{Err: &compiler.Error{Code: compiler.CodeBuildManifest, Err: fmt.Errorf("missing %s", semgrep.ArtifactName)}}
		}
		raw, err := memo.Scan(context.Background(), config)
		if err != nil {
			return compiler.Outcome{Err: err}
		}
		return semgrep.EvalCheck(entry, artifacts, tool.Version, raw, now)
	})
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	if selected == 0 {
		fprintln(stdout, "no checks selected")
	}
	report := compiler.SemgrepReport{
		ReportVersion:  compiler.ReportVersion,
		IpsoVersion:    Version,
		EvaluatedAt:    now.UTC(),
		Env:            opts.env,
		Paths:          opts.paths,
		SemgrepVersion: tool.Version,
		BuildSHA256:    build.SHA256(),
		Verdicts:       verdicts,
	}
	if err := writeOutputs(opts.report, opts.sarif, sarif.Category("semgrep", opts.env, opts.input), checks, func() ([]byte, error) {
		return compiler.MarshalSemgrepReport(report)
	}); err != nil {
		fprintln(stderr, err)
		return 1
	}
	if failed {
		return 1
	}
	return 0
}

func archunitCmd(root string, args []string, stdout, stderr io.Writer, d deps) int {
	opts, err := parsePathArgs(args, archunitUsage, true)
	if err != nil {
		fprintln(stderr, err)
		return 2
	}
	if d.now == nil {
		d.now = time.Now
	}
	build, err := compiler.LoadBuild(root)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	now := d.now()
	selectedCount := 0
	for _, entry := range build.Entries {
		if entry.Engine == "archunit" && entry.Applies(opts.env, now) {
			selectedCount++
		}
	}
	var env *archunit.Env
	var envErr error
	if selectedCount > 0 {
		env, envErr = archunit.Setup(context.Background(), root, opts.jars, opts.paths)
		if envErr == nil {
			defer env.Close()
		}
	}
	verdicts, checks, failed, selected, err := evaluateChecks(d, baseline.Scope{Env: opts.env, Input: opts.input}, stdout, build, func(entry compiler.Entry) bool {
		return entry.Engine == "archunit" && entry.Applies(opts.env, now)
	}, func(entry compiler.Entry, artifacts map[string][]byte) compiler.Outcome {
		if envErr != nil {
			return compiler.Outcome{Err: envErr}
		}
		return env.Evaluate(context.Background(), entry, artifacts, now)
	})
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	if selected == 0 {
		fprintln(stdout, "no checks selected")
	}
	report := compiler.ArchUnitReport{
		ReportVersion: compiler.ReportVersion,
		IpsoVersion:   Version,
		EvaluatedAt:   now.UTC(),
		Env:           opts.env,
		Paths:         opts.paths,
		BuildSHA256:   build.SHA256(),
		Verdicts:      verdicts,
	}
	if envErr == nil && selectedCount > 0 {
		report.ArchUnitVersion = env.Version()
	}
	if err := writeOutputs(opts.report, opts.sarif, sarif.Category("archunit", opts.env, opts.input), checks, func() ([]byte, error) {
		return compiler.MarshalArchUnitReport(report)
	}); err != nil {
		fprintln(stderr, err)
		return 1
	}
	if failed {
		return 1
	}
	return 0
}

func importlinterCmd(root string, args []string, stdout, stderr io.Writer, d deps) int {
	opts, err := parsePathArgs(args, importlinterUsage, false)
	if err != nil {
		fprintln(stderr, err)
		return 2
	}
	if d.now == nil {
		d.now = time.Now
	}
	build, err := compiler.LoadBuild(root)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	now := d.now()
	selectedCount := 0
	for _, entry := range build.Entries {
		if entry.Engine == "importlinter" && entry.Applies(opts.env, now) {
			selectedCount++
		}
	}
	var env *importlinter.Env
	var envErr error
	if selectedCount > 0 {
		env, envErr = importlinter.Setup(context.Background(), root, opts.paths)
		if envErr == nil {
			defer env.Close()
		}
	}
	verdicts, checks, failed, selected, err := evaluateChecks(d, baseline.Scope{Env: opts.env, Input: opts.input}, stdout, build, func(entry compiler.Entry) bool {
		return entry.Engine == "importlinter" && entry.Applies(opts.env, now)
	}, func(entry compiler.Entry, artifacts map[string][]byte) compiler.Outcome {
		if envErr != nil {
			return compiler.Outcome{Err: envErr}
		}
		return env.Evaluate(context.Background(), entry, artifacts, now)
	})
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	if selected == 0 {
		fprintln(stdout, "no checks selected")
	}
	report := compiler.ImportLinterReport{
		ReportVersion: compiler.ReportVersion,
		IpsoVersion:   Version,
		EvaluatedAt:   now.UTC(),
		Env:           opts.env,
		Paths:         opts.paths,
		BuildSHA256:   build.SHA256(),
		Verdicts:      verdicts,
	}
	if envErr == nil && selectedCount > 0 {
		report.ImportLinterVersion = env.Version()
	}
	if err := writeOutputs(opts.report, opts.sarif, sarif.Category("importlinter", opts.env, opts.input), checks, func() ([]byte, error) {
		return compiler.MarshalImportLinterReport(report)
	}); err != nil {
		fprintln(stderr, err)
		return 1
	}
	if failed {
		return 1
	}
	return 0
}

func kyvernoCmd(root string, args []string, stdout, stderr io.Writer, d deps) int {
	opts, err := parsePathArgs(args, kyvernoUsage, false)
	if err != nil {
		fprintln(stderr, err)
		return 2
	}
	if d.now == nil {
		d.now = time.Now
	}
	build, err := compiler.LoadBuild(root)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	now := d.now()
	selectedCount := 0
	for _, entry := range build.Entries {
		if entry.Engine == "kyverno" && entry.Applies(opts.env, now) {
			selectedCount++
		}
	}
	var env *kyverno.Env
	var envErr error
	if selectedCount > 0 {
		env, envErr = kyverno.Setup(context.Background(), root, opts.paths)
		if envErr == nil {
			defer env.Close()
		}
	}
	verdicts, checks, failed, selected, err := evaluateChecks(d, baseline.Scope{Env: opts.env, Input: opts.input}, stdout, build, func(entry compiler.Entry) bool {
		return entry.Engine == "kyverno" && entry.Applies(opts.env, now)
	}, func(entry compiler.Entry, artifacts map[string][]byte) compiler.Outcome {
		if envErr != nil {
			return compiler.Outcome{Err: envErr}
		}
		return env.Evaluate(context.Background(), entry, artifacts, now)
	})
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	if selected == 0 {
		fprintln(stdout, "no checks selected")
	}
	report := compiler.KyvernoReport{
		ReportVersion: compiler.ReportVersion,
		IpsoVersion:   Version,
		EvaluatedAt:   now.UTC(),
		Env:           opts.env,
		Paths:         opts.paths,
		BuildSHA256:   build.SHA256(),
		Verdicts:      verdicts,
	}
	if envErr == nil && selectedCount > 0 {
		report.KyvernoVersion = env.Version()
	}
	if err := writeOutputs(opts.report, opts.sarif, sarif.Category("kyverno", opts.env, opts.input), checks, func() ([]byte, error) {
		return compiler.MarshalKyvernoReport(report)
	}); err != nil {
		fprintln(stderr, err)
		return 1
	}
	if failed {
		return 1
	}
	return 0
}

// isGatekeeperCheck reports whether the entry is a compiled Gatekeeper template and constraint.
func isGatekeeperCheck(entry compiler.Entry) bool {
	return entry.Engine == "opa" && entry.Target == "gatekeeper"
}

func gatekeeperCmd(root string, args []string, stdout, stderr io.Writer, d deps) int {
	opts, err := parsePathArgs(args, gatekeeperUsage, false)
	if err != nil {
		fprintln(stderr, err)
		return 2
	}
	if d.now == nil {
		d.now = time.Now
	}
	build, err := compiler.LoadBuild(root)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	now := d.now()
	selectedCount := 0
	for _, entry := range build.Entries {
		if isGatekeeperCheck(entry) && entry.Applies(opts.env, now) {
			selectedCount++
		}
	}
	var env *gatekeeper.Env
	var envErr error
	if selectedCount > 0 {
		env, envErr = gatekeeper.Setup(context.Background(), root, opts.paths)
		if envErr == nil {
			defer env.Close()
		}
	}
	verdicts, checks, failed, selected, err := evaluateChecks(d, baseline.Scope{Env: opts.env, Input: opts.input}, stdout, build, func(entry compiler.Entry) bool {
		return isGatekeeperCheck(entry) && entry.Applies(opts.env, now)
	}, func(entry compiler.Entry, artifacts map[string][]byte) compiler.Outcome {
		if envErr != nil {
			return compiler.Outcome{Err: envErr}
		}
		return env.Evaluate(context.Background(), entry, artifacts, now)
	})
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	if selected == 0 {
		fprintln(stdout, "no checks selected")
	}
	report := compiler.GatekeeperReport{
		ReportVersion: compiler.ReportVersion,
		IpsoVersion:   Version,
		EvaluatedAt:   now.UTC(),
		Env:           opts.env,
		Paths:         opts.paths,
		BuildSHA256:   build.SHA256(),
		Verdicts:      verdicts,
	}
	if envErr == nil && selectedCount > 0 {
		report.GatorVersion = env.Version()
	}
	if err := writeOutputs(opts.report, opts.sarif, sarif.Category("gatekeeper", opts.env, opts.input), checks, func() ([]byte, error) {
		return compiler.MarshalGatekeeperReport(report)
	}); err != nil {
		fprintln(stderr, err)
		return 1
	}
	if failed {
		return 1
	}
	return 0
}

func eslintCmd(root string, args []string, stdout, stderr io.Writer, d deps) int {
	opts, err := parsePathArgs(args, eslintUsage, false)
	if err != nil {
		fprintln(stderr, err)
		return 2
	}
	if d.now == nil {
		d.now = time.Now
	}
	build, err := compiler.LoadBuild(root)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	now := d.now()
	selectedCount := 0
	for _, entry := range build.Entries {
		if entry.Engine == "eslint" && entry.Applies(opts.env, now) {
			selectedCount++
		}
	}
	var env *eslint.Env
	var envErr error
	if selectedCount > 0 {
		env, envErr = eslint.Setup(context.Background(), root, opts.paths)
		if envErr == nil {
			defer env.Close()
		}
	}
	verdicts, checks, failed, selected, err := evaluateChecks(d, baseline.Scope{Env: opts.env, Input: opts.input}, stdout, build, func(entry compiler.Entry) bool {
		return entry.Engine == "eslint" && entry.Applies(opts.env, now)
	}, func(entry compiler.Entry, artifacts map[string][]byte) compiler.Outcome {
		if envErr != nil {
			return compiler.Outcome{Err: envErr}
		}
		return env.Evaluate(context.Background(), entry, artifacts, now)
	})
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	if selected == 0 {
		fprintln(stdout, "no checks selected")
	}
	report := compiler.ESLintReport{
		ReportVersion: compiler.ReportVersion,
		IpsoVersion:   Version,
		EvaluatedAt:   now.UTC(),
		Env:           opts.env,
		Paths:         opts.paths,
		BuildSHA256:   build.SHA256(),
		Verdicts:      verdicts,
	}
	if envErr == nil && selectedCount > 0 {
		report.ESLintVersion = env.Version()
	}
	if err := writeOutputs(opts.report, opts.sarif, sarif.Category("eslint", opts.env, opts.input), checks, func() ([]byte, error) {
		return compiler.MarshalESLintReport(report)
	}); err != nil {
		fprintln(stderr, err)
		return 1
	}
	if failed {
		return 1
	}
	return 0
}

func depcruiseCmd(root string, args []string, stdout, stderr io.Writer, d deps) int {
	opts, err := parsePathArgs(args, depcruiseUsage, false)
	if err != nil {
		fprintln(stderr, err)
		return 2
	}
	if d.now == nil {
		d.now = time.Now
	}
	build, err := compiler.LoadBuild(root)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	now := d.now()
	selectedCount := 0
	for _, entry := range build.Entries {
		if entry.Engine == "depcruise" && entry.Applies(opts.env, now) {
			selectedCount++
		}
	}
	var tool depcruise.Tool
	var toolErr error
	if selectedCount > 0 {
		tool, toolErr = depcruise.FindTool(context.Background())
	}
	memo := depcruise.Memo{Tool: tool, Root: root, Paths: opts.paths}
	verdicts, checks, failed, selected, err := evaluateChecks(d, baseline.Scope{Env: opts.env, Input: opts.input}, stdout, build, func(entry compiler.Entry) bool {
		return entry.Engine == "depcruise" && entry.Applies(opts.env, now)
	}, func(entry compiler.Entry, artifacts map[string][]byte) compiler.Outcome {
		if toolErr != nil {
			return compiler.Outcome{Err: toolErr}
		}
		if !depcruise.VersionFits(tool.Version, entry.CompilerVersion) {
			return compiler.Outcome{Err: &compiler.Error{Code: depcruise.CodeVersion, Err: fmt.Errorf("depcruise %s does not satisfy ^%s", tool.Version, entry.CompilerVersion)}}
		}
		config, ok := artifacts[depcruise.ArtifactName]
		if !ok {
			return compiler.Outcome{Err: &compiler.Error{Code: compiler.CodeBuildManifest, Err: fmt.Errorf("missing %s", depcruise.ArtifactName)}}
		}
		raw, err := memo.Cruise(context.Background(), config)
		if err != nil {
			return compiler.Outcome{Err: err}
		}
		return depcruise.EvalCheck(entry, artifacts, tool.Version, raw, now)
	})
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	if selected == 0 {
		fprintln(stdout, "no checks selected")
	}
	report := compiler.DepcruiseReport{
		ReportVersion:    compiler.ReportVersion,
		IpsoVersion:      Version,
		EvaluatedAt:      now.UTC(),
		Env:              opts.env,
		Paths:            opts.paths,
		DepcruiseVersion: tool.Version,
		BuildSHA256:      build.SHA256(),
		Verdicts:         verdicts,
	}
	if err := writeOutputs(opts.report, opts.sarif, sarif.Category("depcruise", opts.env, opts.input), checks, func() ([]byte, error) {
		return compiler.MarshalDepcruiseReport(report)
	}); err != nil {
		fprintln(stderr, err)
		return 1
	}
	if failed {
		return 1
	}
	return 0
}

func openInput(path string) (io.ReadCloser, error) {
	if path == "-" {
		return io.NopCloser(os.Stdin), nil
	}
	return os.Open(path)
}

type planOptions struct {
	path   string
	env    string
	input  string
	report string
	sarif  string
	bundle string
	digest string
	key    string
}

func parsePlanArgs(args []string) (planOptions, error) {
	var opts planOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--env":
			if opts.env != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return planOptions{}, fmt.Errorf("%s", planUsage)
			}
			i++
			opts.env = args[i]
		case "--input":
			if opts.input != "" || i+1 >= len(args) || !baseline.ValidInput(args[i+1]) {
				return planOptions{}, fmt.Errorf("%s", planUsage)
			}
			i++
			opts.input = args[i]
		case "--report":
			if opts.report != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return planOptions{}, fmt.Errorf("%s", planUsage)
			}
			i++
			opts.report = args[i]
		case "--sarif":
			if opts.sarif != "" || i+1 >= len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "-") {
				return planOptions{}, fmt.Errorf("%s", planUsage)
			}
			i++
			opts.sarif = args[i]
		case "--bundle":
			if opts.bundle != "" || i+1 >= len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "-") {
				return planOptions{}, fmt.Errorf("%s", planUsage)
			}
			i++
			opts.bundle = args[i]
		case "--digest":
			if opts.digest != "" || i+1 >= len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "-") {
				return planOptions{}, fmt.Errorf("%s", planUsage)
			}
			i++
			opts.digest = args[i]
		case "--key":
			if opts.key != "" || i+1 >= len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "-") {
				return planOptions{}, fmt.Errorf("%s", planUsage)
			}
			i++
			opts.key = args[i]
		default:
			if strings.HasPrefix(args[i], "-") || opts.path != "" {
				return planOptions{}, fmt.Errorf("%s", planUsage)
			}
			opts.path = args[i]
		}
	}
	if opts.path == "" || sameOutput(opts.report, opts.sarif) {
		return planOptions{}, fmt.Errorf("%s", planUsage)
	}
	if (opts.bundle != "") != (opts.digest != "") || (opts.bundle != "") != (opts.key != "") {
		return planOptions{}, fmt.Errorf("%s", planUsage)
	}
	if opts.digest != "" && !bundle.ValidDigest(opts.digest) {
		return planOptions{}, fmt.Errorf("%s", planUsage)
	}
	return opts, nil
}

type cruiseOptions struct {
	paths  []string
	env    string
	input  string
	report string
	sarif  string
	jars   string
}

// parsePathArgs reads the paths and options of a command that runs an engine over repository paths.
// jars is true for the command that takes --jars, and then that option is required.
func parsePathArgs(args []string, usage string, jars bool) (cruiseOptions, error) {
	var opts cruiseOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--jars":
			if !jars || opts.jars != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return cruiseOptions{}, fmt.Errorf("%s", usage)
			}
			i++
			opts.jars = args[i]
		case "--env":
			if opts.env != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return cruiseOptions{}, fmt.Errorf("%s", usage)
			}
			i++
			opts.env = args[i]
		case "--input":
			if opts.input != "" || i+1 >= len(args) || !baseline.ValidInput(args[i+1]) {
				return cruiseOptions{}, fmt.Errorf("%s", usage)
			}
			i++
			opts.input = args[i]
		case "--report":
			if opts.report != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return cruiseOptions{}, fmt.Errorf("%s", usage)
			}
			i++
			opts.report = args[i]
		case "--sarif":
			if opts.sarif != "" || i+1 >= len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "-") {
				return cruiseOptions{}, fmt.Errorf("%s", usage)
			}
			i++
			opts.sarif = args[i]
		default:
			if strings.HasPrefix(args[i], "-") {
				return cruiseOptions{}, fmt.Errorf("%s", usage)
			}
			cleaned, err := toolrun.NormalizePath(args[i])
			if err != nil {
				return cruiseOptions{}, fmt.Errorf("%s", usage)
			}
			opts.paths = append(opts.paths, cleaned)
		}
	}
	if len(opts.paths) == 0 || (jars && opts.jars == "") || sameOutput(opts.report, opts.sarif) {
		return cruiseOptions{}, fmt.Errorf("%s", usage)
	}
	return opts, nil
}

type boundOptions struct {
	path   string
	env    string
	input  string
	report string
	sarif  string
	sha    string
}

func parseBoundArgs(args []string, usage string, sha bool) (boundOptions, error) {
	var opts boundOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--env":
			if opts.env != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return boundOptions{}, fmt.Errorf("%s", usage)
			}
			i++
			opts.env = args[i]
		case "--input":
			if sha || opts.input != "" || i+1 >= len(args) || !baseline.ValidInput(args[i+1]) {
				return boundOptions{}, fmt.Errorf("%s", usage)
			}
			i++
			opts.input = args[i]
		case "--report":
			if opts.report != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return boundOptions{}, fmt.Errorf("%s", usage)
			}
			i++
			opts.report = args[i]
		case "--sarif":
			if opts.sarif != "" || i+1 >= len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "-") {
				return boundOptions{}, fmt.Errorf("%s", usage)
			}
			i++
			opts.sarif = args[i]
		case "--sha":
			if !sha || opts.sha != "" || i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return boundOptions{}, fmt.Errorf("%s", usage)
			}
			i++
			opts.sha = args[i]
		default:
			if strings.HasPrefix(args[i], "-") || opts.path != "" {
				return boundOptions{}, fmt.Errorf("%s", usage)
			}
			opts.path = args[i]
		}
	}
	if opts.path == "" || (sha && opts.sha == "") || sameOutput(opts.report, opts.sarif) {
		return boundOptions{}, fmt.Errorf("%s", usage)
	}
	return opts, nil
}

// writeReport replaces path with raw. A symlink is refused. The file mode is 0600.
func writeReport(path string, raw []byte) error {
	info, err := os.Lstat(path)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink", path)
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(path)
	parent, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if parent.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink", dir)
	}
	temp, err := os.CreateTemp(dir, ".report-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tempName)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(raw); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// evaluateChecks runs match against the build and prints one line per selected check.
// hard is true when a block-mode check fails or any check errors.
func evaluateChecks(d deps, scope baseline.Scope, stdout io.Writer, build compiler.Build, match func(compiler.Entry) bool, eval func(compiler.Entry, map[string][]byte) compiler.Outcome) (verdicts []compiler.Verdict, checks []sarif.Check, hard bool, selected int, err error) {
	for _, entry := range build.Entries {
		if !match(entry) {
			continue
		}
		selected++
		artifacts, artErr := build.Artifacts(entry)
		if artErr != nil {
			return nil, nil, true, selected, artErr
		}
		outcome := eval(entry, artifacts)
		if d.capture == nil {
			outcome, err = baseline.Apply(entry, scope, outcome)
			if err != nil {
				return nil, nil, true, selected, err
			}
		}
		verdict, failed := verdictOf(stdout, entry, outcome)
		if failed {
			hard = true
		}
		verdicts = append(verdicts, verdict)
		checks = append(checks, sarif.Check{Entry: entry, Outcome: outcome})
	}
	if d.capture != nil {
		d.capture.done = true
		d.capture.scope = scope
		d.capture.checks = checks
	}
	return verdicts, checks, hard, selected, nil
}

// writeOutputs writes the files a check command was asked for. Both are encoded first, so a file that
// cannot be encoded leaves neither one behind.
func writeOutputs(reportPath, sarifPath, category string, checks []sarif.Check, marshal func() ([]byte, error)) error {
	var report, results []byte
	var err error
	if reportPath != "" {
		if report, err = marshal(); err != nil {
			return err
		}
	}
	if sarifPath != "" {
		if results, err = sarif.Marshal(Version, category, checks); err != nil {
			return err
		}
	}
	if reportPath != "" {
		if err := writeReport(reportPath, report); err != nil {
			return err
		}
	}
	if sarifPath != "" {
		return writeReport(sarifPath, results)
	}
	return nil
}

// sameOutput reports whether both flags name one file. A path that cannot be made absolute is compared as written.
func sameOutput(report, sarifPath string) bool {
	if report == "" || sarifPath == "" {
		return false
	}
	reportAbs, reportErr := filepath.Abs(report)
	sarifAbs, sarifErr := filepath.Abs(sarifPath)
	if reportErr != nil || sarifErr != nil {
		return filepath.Clean(report) == filepath.Clean(sarifPath)
	}
	return reportAbs == sarifAbs
}

func verdictOf(stdout io.Writer, entry compiler.Entry, outcome compiler.Outcome) (compiler.Verdict, bool) {
	verdict := compiler.Verdict{
		DecisionID: entry.DecisionID,
		Slug:       entry.Slug,
		CheckIndex: entry.CheckIndex,
		Mode:       entry.Mode,
		Result:     "pass",
	}
	switch {
	case outcome.Err != nil:
		verdict.Result = "error"
		fprintf(stdout, "%s: checks[%d] (%s): error: %s\n", entry.Slug, entry.CheckIndex, entry.Mode, outcome.Err)
		return verdict, true
	case len(outcome.Violations) > 0 && outcome.Waived:
		verdict.Result = "waived"
		verdict.Violations = len(outcome.Violations)
		fprintf(stdout, "%s: checks[%d] (%s): waived\n", entry.Slug, entry.CheckIndex, entry.Mode)
		return verdict, false
	case len(outcome.Violations) > 0:
		covered := 0
		for _, violation := range outcome.Violations {
			if violation.Baselined {
				covered++
			}
		}
		if covered == len(outcome.Violations) {
			verdict.Result = "waived"
			verdict.Violations = covered
			fprintf(stdout, "%s: checks[%d] (%s): waived (baseline: %d)\n", entry.Slug, entry.CheckIndex, entry.Mode, covered)
			return verdict, false
		}
		verdict.Result = "fail"
		verdict.Violations = len(outcome.Violations) - covered
		for _, violation := range outcome.Violations {
			if !violation.Baselined {
				fprintf(stdout, "%s: checks[%d] (%s): %s\n", entry.Slug, entry.CheckIndex, entry.Mode, violationLine(violation))
			}
		}
		if covered > 0 {
			fprintf(stdout, "%s: checks[%d] (%s): baselined: %d\n", entry.Slug, entry.CheckIndex, entry.Mode, covered)
		}
		return verdict, entry.Mode == "block"
	default:
		fprintf(stdout, "%s: checks[%d] (%s): pass\n", entry.Slug, entry.CheckIndex, entry.Mode)
		return verdict, false
	}
}

func violationLine(violation compiler.Violation) string {
	if violation.Address == "" {
		return violation.Message
	}
	return violation.Address + ": " + violation.Message
}

func explainCmd(root, slug string, stdout, stderr io.Writer) int {
	cfg, _, err := config.Load(root)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	files, err := edr.Match(root, cfg.Decisions)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	var found []string
	var chosen edr.Document
	for _, path := range files {
		doc, err := edr.ReadFile(path)
		if err != nil {
			continue
		}
		if doc.Slug() != slug {
			continue
		}
		found = append(found, path)
		chosen = doc
	}
	if len(found) == 0 {
		fprintf(stderr, "no EDR file with slug %q\n", slug)
		return 1
	}
	if len(found) > 1 {
		fprintf(stderr, "more than one EDR file with slug %q\n", slug)
		return 1
	}
	text, ok := edr.DecisionText(chosen.Body)
	if !ok {
		fprintf(stderr, "%s: missing heading ## Decision\n", displayPath(root, found[0]))
		return 1
	}
	fprintf(stdout, "title: %s\nstatus: %s\nid: %s\npath: %s\n", chosen.Title(), chosen.Status(), compiler.EscapeControls(chosen.ID()), compiler.EscapeControls(displayPath(root, found[0])))
	if sources := chosen.Sources(); len(sources) > 0 {
		fprintln(stdout, "sources:")
		for _, source := range sources {
			fprintf(stdout, "  - %s %s\n", compiler.EscapeControls(source.Type), compiler.EscapeControls(source.URL))
		}
	}
	fprintf(stdout, "\n%s\n", text)
	return 0
}

func compileCmd(root string, stdout, stderr io.Writer, d deps) int {
	if d.now == nil {
		d.now = time.Now
	}
	cfg, _, err := config.Load(root)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	files, err := edr.Match(root, cfg.Decisions)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	if len(files) == 0 {
		fprintln(stdout, "no EDR files found")
		if err := compiler.WriteBuild(root, nil, nil); err != nil {
			fprintln(stderr, err)
			return 1
		}
		return 0
	}
	type loaded struct {
		shown string
		title string
		rec   edr.Record
	}
	var docs []loaded
	failed := false
	for _, path := range files {
		shown := displayPath(root, path)
		doc, err := edr.ReadFile(path)
		if err != nil {
			fprintf(stdout, "%s: %s\n", shown, err)
			failed = true
			continue
		}
		problems := edr.Validate(doc)
		if len(problems) > 0 {
			failed = true
			for _, problem := range problems {
				fprintf(stdout, "%s: %s\n", shown, problem)
			}
			continue
		}
		rec, err := edr.RecordFrom(doc)
		if err != nil {
			fprintf(stdout, "%s: %s\n", shown, err)
			failed = true
			continue
		}
		docs = append(docs, loaded{shown: shown, title: doc.Title(), rec: rec})
	}
	if failed {
		return 1
	}

	repo, err := os.OpenRoot(root)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	defer func() { _ = repo.Close() }()

	now := d.now()
	var ids []compiler.DecisionRef
	var compiled []compiler.Compiled
	var lines []string
	seen := map[string]string{}
	for _, item := range docs {
		if !item.rec.InForce(now) {
			lines = append(lines, fmt.Sprintf("%s: skipped, not in force", item.shown))
			continue
		}
		if prev, ok := seen[item.rec.ID]; ok {
			fprintf(stdout, "%s: duplicate-id: %s\n", item.shown, prev)
			return 1
		}
		seen[item.rec.ID] = item.shown
		ids = append(ids, compiler.DecisionRef{Path: item.shown, ID: item.rec.ID})
		part, reports, err := compiler.CompileRecord(d.registry, item.rec, repo.FS())
		if err != nil {
			fprintf(stdout, "%s: %s\n", item.shown, err)
			return 1
		}
		// A file outside the repository gets no path, and only --sarif refuses that build.
		if compiler.ValidRepoPath(item.shown) {
			for i := range part {
				part[i].Entry.Path = item.shown
				part[i].Entry.Title = item.title
			}
		}
		compiled = append(compiled, part...)
		for _, report := range reports {
			lines = append(lines, compileLine(item.shown, report))
		}
	}
	baselined, err := stampBaseline(root, compiled)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	lines = append(lines, baselined...)
	if err := compiler.WriteBuild(root, ids, compiled); err != nil {
		fprintln(stderr, err)
		return 1
	}
	for _, line := range lines {
		fprintln(stdout, line)
	}
	return 0
}

func compileLine(shown string, report compiler.Report) string {
	switch report.Kind {
	case compiler.ReportAdvisory:
		return fmt.Sprintf("%s: checks[%d] (%s): advisory, not compiled", shown, report.Index, report.Engine)
	case compiler.ReportNoCompiler:
		return fmt.Sprintf("%s: checks[%d] (%s): no compiler", shown, report.Index, report.Engine)
	default:
		word := "artifacts"
		if report.Count == 1 {
			word = "artifact"
		}
		return fmt.Sprintf("%s: checks[%d] (%s): compiled %d %s", shown, report.Index, report.Engine, report.Count, word)
	}
}

func importCmd(root string, args []string, stdout, stderr io.Writer) int {
	targets, err := importTargets(root, args)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	if len(targets) == 0 {
		fprintln(stdout, "no ADR files found")
		return 0
	}
	failed := false
	for _, path := range targets {
		shown := displayPath(root, path)
		raw, err := os.ReadFile(path)
		if err != nil {
			fprintf(stdout, "%s: %s\n", shown, err)
			failed = true
			continue
		}
		if doc, err := edr.Parse(string(raw)); err == nil && len(edr.Validate(doc)) == 0 {
			fprintf(stdout, "%s: skipped\n", shown)
			continue
		}
		imported, err := edr.Import(filepath.Base(path), string(raw), time.Now())
		if err != nil {
			fprintf(stdout, "%s: %s\n", shown, err)
			failed = true
			continue
		}
		if err := os.WriteFile(path, []byte(imported), 0o644); err != nil {
			fprintf(stdout, "%s: %s\n", shown, err)
			failed = true
			continue
		}
		if strings.Contains(imported, "\ninferred: true\n") {
			fprintf(stdout, "%s: imported inferred\n", shown)
			continue
		}
		fprintf(stdout, "%s: imported\n", shown)
	}
	if failed {
		return 1
	}
	return 0
}

func importTargets(root string, args []string) ([]string, error) {
	if len(args) == 0 {
		var found []string
		for _, dir := range []string{"docs/adr", "docs/decisions"} {
			path := filepath.Join(root, filepath.FromSlash(dir))
			info, err := os.Stat(path)
			if err != nil || !info.IsDir() {
				continue
			}
			files, err := markdownFiles(path)
			if err != nil {
				return nil, err
			}
			found = append(found, files...)
		}
		return found, nil
	}
	var found []string
	for _, arg := range args {
		if arg == "" {
			return nil, fmt.Errorf("usage: ipso import [path...]")
		}
		path := arg
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, path)
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			found = append(found, path)
			continue
		}
		files, err := markdownFiles(path)
		if err != nil {
			return nil, err
		}
		found = append(found, files...)
	}
	return found, nil
}

func markdownFiles(root string) ([]string, error) {
	var found []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ".md") {
			found = append(found, path)
		}
		return nil
	})
	return found, err
}

func fprintf(w io.Writer, format string, args ...any) {
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		return
	}
}

func fprintln(w io.Writer, args ...any) {
	if _, err := fmt.Fprintln(w, args...); err != nil {
		return
	}
}

func displayPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}
