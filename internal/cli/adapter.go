package cli

import (
	"io"
	"time"

	"github.com/ipsofacto-io/ipso/internal/adapter"
	"github.com/ipsofacto-io/ipso/internal/baseline"
	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/opa"
	"github.com/ipsofacto-io/ipso/internal/sarif"
)

const (
	pulumiUsage         = "usage: ipso check pulumi <preview.json|-> [--env name] [--input name] [--report file] [--sarif file]"
	cloudformationUsage = "usage: ipso check cloudformation <template|-> [--env name] [--input name] [--report file] [--sarif file]"
	armUsage            = "usage: ipso check arm <template.json|-> [--env name] [--input name] [--report file] [--sarif file]"
)

// adapterCheck is one adapter family: its command, the check target it serves, and its reader.
type adapterCheck struct {
	name    string
	usage   string
	target  string
	convert func([]byte) ([]byte, error)
}

var (
	pulumiCheck         = adapterCheck{name: "pulumi", usage: pulumiUsage, target: adapter.TargetPulumi, convert: adapter.Pulumi}
	cloudformationCheck = adapterCheck{name: "cloudformation", usage: cloudformationUsage, target: adapter.TargetCloudFormation, convert: adapter.CloudFormation}
	armCheck            = adapterCheck{name: "arm", usage: armUsage, target: adapter.TargetARM, convert: adapter.ARM}
)

// adapterCmd evaluates the compiled OPA checks of one target against one converted input, with the
// rules of ipso check plan. The report hashes the input as read, so it agrees with sha256sum of the file.
func adapterCmd(root string, args []string, check adapterCheck, stdout, stderr io.Writer, d deps) int {
	opts, err := parseBoundArgs(args, check.usage, false)
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
	raw, err := adapter.Read(reader)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	document, err := check.convert(raw)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	input, err := opa.NewInput(raw, document)
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
		return entry.SelectedFor(check.target, opts.env, now)
	}, func(entry compiler.Entry, artifacts map[string][]byte) compiler.Outcome {
		return opa.EvalCheck(entry, artifacts, input, now)
	})
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	if selected == 0 {
		fprintln(stdout, "no checks selected")
	}
	report := compiler.AdapterReport{
		ReportVersion: compiler.ReportVersion,
		IpsoVersion:   Version,
		EvaluatedAt:   now.UTC(),
		Env:           opts.env,
		Adapter:       check.name,
		InputSHA256:   input.SHA256(),
		BuildSHA256:   build.SHA256(),
		Verdicts:      verdicts,
	}
	if err := writeOutputs(opts.report, opts.sarif, sarif.Category(check.name, opts.env, opts.input), checks, func() ([]byte, error) {
		return compiler.MarshalAdapterReport(report)
	}); err != nil {
		fprintln(stderr, err)
		return 1
	}
	if failed {
		return 1
	}
	return 0
}
