package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/builtin"
)

const denyPublic = `package sample.public

deny contains violation if {
	some resource in input.resource_changes
	resource.change.after.public == true
	violation := {"msg": "MESSAGE-MARKER no public resources", "address": resource.address}
}
`

// adapterRepo compiles one decision whose only check serves target.
func adapterRepo(t *testing.T, now time.Time, target, criticality string) string {
	t.Helper()
	root := t.TempDir()
	withDir(t, root)
	checks := "  - engine: opa\n    target: " + target + "\n    ref: policies/public.rego\n"
	writeRepoFile(t, root, "docs/decisions/public.md", compileRecord(idA, "no-public", "accepted", criticality, "2026-01-01", "", checks))
	writeRepoFile(t, root, "policies/public.rego", denyPublic)
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", stderr)
	}
	return root
}

func adapterAt(t *testing.T, now time.Time, args ...string) (string, string, int) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := run(append([]string{"check"}, args...), &stdout, &stderr, deps{now: func() time.Time { return now }, registry: builtin.Registry()})
	return stdout.String(), stderr.String(), code
}

var adapterCases = []struct {
	command string
	target  string
	file    string
	bad     string
	good    string
}{
	{
		command: "pulumi",
		target:  "pulumi-preview",
		file:    "preview.json",
		bad:     `{"steps":[{"op":"create","urn":"urn:pulumi:dev::a::t::r","newState":{"type":"t","inputs":{"public":true}}}]}`,
		good:    `{"steps":[{"op":"create","urn":"urn:pulumi:dev::a::t::r","newState":{"type":"t","inputs":{"public":false}}}]}`,
	},
	{
		command: "cloudformation",
		target:  "cloudformation-template",
		file:    "template.yaml",
		bad:     "Resources:\n  R:\n    Type: T\n    Properties:\n      public: true\n",
		good:    "Resources:\n  R:\n    Type: T\n    Properties:\n      public: false\n",
	},
	{
		command: "arm",
		target:  "arm-template",
		file:    "main.json",
		bad:     `{"$schema":"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#","resources":[{"type":"T","name":"r","public":true}]}`,
		good:    `{"$schema":"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#","resources":[{"type":"T","name":"r","public":false}]}`,
	},
}

func TestAdapterChecks(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range adapterCases {
		t.Run(tc.command, func(t *testing.T) {
			root := adapterRepo(t, now, tc.target, "blocking")

			writeRepoFile(t, root, tc.file, tc.good)
			stdout, stderr, code := adapterAt(t, now, tc.command, tc.file)
			if code != 0 || !strings.Contains(stdout, "no-public: checks[0] (block): pass") {
				t.Fatalf("good code %d\n%s\n%s", code, stdout, stderr)
			}

			writeRepoFile(t, root, tc.file, tc.bad)
			report := filepath.Join(root, "report.json")
			results := filepath.Join(root, "results.sarif")
			stdout, stderr, code = adapterAt(t, now, tc.command, tc.file, "--report", report, "--sarif", results)
			if code != 1 || !strings.Contains(stdout, "no-public: checks[0] (block): ") || !strings.Contains(stdout, "MESSAGE-MARKER") {
				t.Fatalf("bad code %d\n%s\n%s", code, stdout, stderr)
			}
			body, err := os.ReadFile(report)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(body), "MESSAGE-MARKER") {
				t.Fatalf("report holds the message: %s", body)
			}
			var decoded compiler.AdapterReport
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.Adapter != tc.command || len(decoded.InputSHA256) != 64 || len(decoded.Verdicts) != 1 || decoded.Verdicts[0].Result != "fail" {
				t.Fatalf("report %s", body)
			}
			if _, err := os.Stat(results); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAdapterWarningDoesNotBlock(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	tc := adapterCases[1]
	root := adapterRepo(t, now, tc.target, "warning")
	writeRepoFile(t, root, tc.file, tc.bad)
	stdout, stderr, code := adapterAt(t, now, tc.command, tc.file)
	if code != 0 || !strings.Contains(stdout, "(warn): ") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestAdapterChecksOnlySelectTheirTarget(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := adapterRepo(t, now, "cloudformation-template", "blocking")
	for _, tc := range adapterCases {
		writeRepoFile(t, root, tc.file, tc.bad)
	}
	stdout, stderr, code := adapterAt(t, now, "pulumi", "preview.json")
	if code != 0 || !strings.Contains(stdout, "no checks selected") {
		t.Fatalf("pulumi code %d\n%s\n%s", code, stdout, stderr)
	}
	stdout, stderr, code = adapterAt(t, now, "cloudformation", "template.yaml")
	if code != 1 || !strings.Contains(stdout, "(block): ") {
		t.Fatalf("cloudformation code %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestPlanChecksIgnoreAdapterTargets(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := adapterRepo(t, now, "cloudformation-template", "blocking")
	writeRepoFile(t, root, "plan.json", `{"format_version":"1.2","resource_changes":[{"address":"a.b","type":"a","change":{"after":{"public":true}}}]}`)
	stdout, stderr, code := planAt(t, now, []string{"plan.json"})
	if code != 0 || !strings.Contains(stdout, "no checks selected") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestAdapterFailures(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range adapterCases {
		t.Run(tc.command, func(t *testing.T) {
			root := adapterRepo(t, now, tc.target, "blocking")
			stdout, stderr, code := adapterAt(t, now, tc.command, "missing.json")
			if code != 1 || stdout != "" || stderr == "" {
				t.Fatalf("missing code %d\n%s\n%s", code, stdout, stderr)
			}
			writeRepoFile(t, root, tc.file, "{}")
			stdout, stderr, code = adapterAt(t, now, tc.command, tc.file)
			if code != 1 || stdout != "" || !strings.Contains(stderr, "adapter-format") {
				t.Fatalf("not the format code %d\n%s\n%s", code, stdout, stderr)
			}
			writeRepoFile(t, root, tc.file, tc.good)
			if err := os.RemoveAll(filepath.Join(root, ".ipso", "build")); err != nil {
				t.Fatal(err)
			}
			stdout, stderr, code = adapterAt(t, now, tc.command, tc.file)
			if code != 1 || !strings.Contains(stderr, "build-missing") {
				t.Fatalf("no build code %d\n%s\n%s", code, stdout, stderr)
			}
		})
	}
}

func TestAdapterUsage(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	withDir(t, t.TempDir())
	for _, command := range []string{"pulumi", "cloudformation", "arm"} {
		for _, args := range [][]string{
			{},
			{"a", "b"},
			{"--bogus"},
			{"a", "--sha", "abc"},
			{"a", "--env"},
			{"a", "--report", "same", "--sarif", "same"},
		} {
			stdout, stderr, code := adapterAt(t, now, append([]string{command}, args...)...)
			if code != 2 || stdout != "" || !strings.Contains(stderr, "usage: ipso check "+command) {
				t.Fatalf("%s %q code %d\n%s\n%s", command, args, code, stdout, stderr)
			}
		}
	}
}

func TestAdapterCommandsAreListed(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := run([]string{"help"}, &stdout, &stderr, deps{registry: builtin.Registry()}); code != 0 {
		t.Fatalf("code %d", code)
	}
	for _, want := range []string{"ipso check pulumi", "ipso check cloudformation", "ipso check arm"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("help has no %q", want)
		}
	}
	stderr.Reset()
	if code := run([]string{"check", "bogus"}, &stdout, &stderr, deps{registry: builtin.Registry()}); code != 2 || !strings.Contains(stderr.String(), armUsage) {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
}

func TestAdapterBaseline(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	tc := adapterCases[1]
	root := adapterRepo(t, now, tc.target, "blocking")
	writeRepoFile(t, root, tc.file, tc.bad)
	var stdout, stderr strings.Builder
	d := deps{now: func() time.Time { return now }, registry: builtin.Registry()}
	if code := run([]string{"baseline", "create", tc.command, tc.file}, &stdout, &stderr, d); code != 0 {
		t.Fatalf("baseline %d\n%s\n%s", code, stdout.String(), stderr.String())
	}
	if _, errOut, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", errOut)
	}
	out, errOut, code := adapterAt(t, now, tc.command, tc.file)
	if code != 0 || !strings.Contains(out, "waived (baseline: 1)") {
		t.Fatalf("code %d\n%s\n%s", code, out, errOut)
	}
}
