package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler/builtin"
	"github.com/ipsofacto-io/ipso/internal/sarif/sariftest"
)

// sarifLog is the part of a SARIF file these tests read.
type sarifLog struct {
	Runs []struct {
		AutomationDetails struct {
			ID string `json:"id"`
		} `json:"automationDetails"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			RelatedLocations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
				} `json:"physicalLocation"`
			} `json:"relatedLocations"`
			Suppressions []struct {
				Kind string `json:"kind"`
			} `json:"suppressions"`
		} `json:"results"`
	} `json:"runs"`
}

// readSARIF validates the file against the vendored schema and decodes it.
func readSARIF(t *testing.T, path string) (sarifLog, string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sariftest.Validate(t, raw)
	var out sarifLog
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out, string(raw)
}

func TestCheckPlanSARIFPrivacy(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	withDir(t, root)
	record := compileRecord(idA, "ebs-encrypted", "accepted", "blocking", "2026-01-01", "", "  - engine: opa\n    target: terraform-plan\n    ref: ipso:aws/ebs-encrypted\n")
	writeRepoFile(t, root, "docs/decisions/ebs.md", record)
	marker := "secret-bucket-name-9f3a"
	body := strings.Replace(planBody, `"after_unknown":{}`, `"after_unknown":{},"bucket":"`+marker+`"`, 1)
	writeRepoFile(t, root, "plan.json", body)
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", stderr)
	}
	output := filepath.Join(root, "out.sarif")
	stdout, stderr, code := planAt(t, now, []string{"plan.json", "--sarif", output})
	if code != 1 {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	got, text := readSARIF(t, output)
	for _, leaked := range []string{marker, "aws_ebs_volume", "must be encrypted"} {
		if strings.Contains(text, leaked) {
			t.Fatalf("SARIF contains %q: %s", leaked, text)
		}
	}
	if !strings.Contains(stdout, "aws_ebs_volume.data") {
		t.Fatalf("the terminal lost the finding: %s", stdout)
	}
	run := got.Runs[0]
	if run.AutomationDetails.ID != "ipso/plan/" || len(run.Results) != 1 {
		t.Fatalf("run %+v", run)
	}
	result := run.Results[0]
	if result.Level != "error" || result.RuleID != idA+"/0" {
		t.Fatalf("result %+v", result)
	}
	if uri := result.Locations[0].PhysicalLocation.ArtifactLocation.URI; uri != "docs/decisions/ebs.md" {
		t.Fatalf("location %s", uri)
	}
	if uri := result.RelatedLocations[0].PhysicalLocation.ArtifactLocation.URI; uri != "docs/decisions/ebs.md" {
		t.Fatalf("related location %s", uri)
	}
	if !strings.Contains(result.Message.Text, "[decision](1)") {
		t.Fatalf("message %q", result.Message.Text)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
}

func TestCheckSemgrepSARIFLocatesFindings(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	checks := "  - engine: semgrep\n    target: code\n    ref: rules/no-eval.yaml\n"
	root := semgrepRepo(t, now, checks, false)
	withSemgrep(t, "1.182.1", semgrepScan(semgrepHit, "1.182.1"))
	output := filepath.Join(root, "out.sarif")
	_, stderr, code := semgrepAt(t, now, []string{".", "--sarif", output})
	if code != 1 {
		t.Fatalf("code %d %s", code, stderr)
	}
	got, text := readSARIF(t, output)
	if strings.Contains(text, "secret message") || strings.Contains(text, "no-eval") {
		t.Fatalf("engine text leaked: %s", text)
	}
	location := got.Runs[0].Results[0].Locations[0].PhysicalLocation
	if location.ArtifactLocation.URI != "secret.py" || location.Region.StartLine != 3 {
		t.Fatalf("location %+v", location)
	}
}

func TestCheckSemgrepSARIFWaiver(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	checks := "  - engine: semgrep\n    target: code\n    ref: rules/no-eval.yaml\n"
	root := semgrepRepo(t, now, checks, true)
	withSemgrep(t, "1.182.1", semgrepScan(semgrepHit, "1.182.1"))
	output := filepath.Join(root, "out.sarif")
	_, stderr, code := semgrepAt(t, now, []string{".", "--sarif", output})
	if code != 0 {
		t.Fatalf("code %d %s", code, stderr)
	}
	got, text := readSARIF(t, output)
	if strings.Contains(text, "Ada Lovelace") || strings.Contains(text, "cutover") {
		t.Fatalf("waiver detail leaked: %s", text)
	}
	if results := got.Runs[0].Results; len(results) != 1 || len(results[0].Suppressions) != 1 || results[0].Suppressions[0].Kind != "external" {
		t.Fatalf("results %+v", results)
	}
	result := got.Runs[0].Results[0]
	if result.Level != "note" || !strings.HasPrefix(result.Message.Text, "Waived: ") {
		t.Fatalf("result %+v", result)
	}
}

// Every subcommand writes a schema-valid file with its own category. A check with no artifact fails to
// evaluate on every engine, and PATH is empty, so no engine binary runs.
func TestEverySubcommandWritesSARIF(t *testing.T) {
	cases := []struct {
		name, engine, target string
		args                 []string
	}{
		{"plan", "opa", "terraform-plan", []string{"input.json"}},
		{"ci", "ci-binding", "ci", []string{"evidence.json", "--sha", strings.Repeat("a", 40)}},
		{"checkov", "checkov", "terraform", []string{"input.json"}},
		{"depcruise", "depcruise", "code", []string{"."}},
		{"semgrep", "semgrep", "code", []string{"."}},
		{"archunit", "archunit", "code", []string{".", "--jars", "."}},
		{"importlinter", "importlinter", "code", []string{"."}},
		{"kyverno", "kyverno", "kubernetes", []string{"."}},
		{"gatekeeper", "opa", "gatekeeper", []string{"."}},
		{"eslint", "eslint", "code", []string{"."}},
	}
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			withDir(t, root)
			t.Setenv("PATH", t.TempDir())
			manifest := fmt.Sprintf(`{"entries":[{"decision_id":%q,"slug":"one","path":"docs/decisions/one.md","title":"One","check_index":0,"engine":%q,"mode":"block","target":%q,"valid_from":"2026-01-01","valid_to":null,"env":null,"waivers":[],"compiler":"x","compiler_version":"1","artifacts":[]}]}`, idA, tc.engine, tc.target)
			writeRepoFile(t, root, ".ipso/build/manifest.json", manifest)
			writeRepoFile(t, root, "input.json", planBody)
			writeRepoFile(t, root, "evidence.json", `{"evidence_version":1,"sha":"`+strings.Repeat("a", 40)+`","jobs":[]}`)
			output := filepath.Join(root, "out.sarif")
			var stdout, stderr strings.Builder
			args := append(append([]string{"check", tc.name}, tc.args...), "--sarif", output)
			run(args, &stdout, &stderr, deps{now: func() time.Time { return now }, registry: builtin.Registry()})
			got, _ := readSARIF(t, output)
			if id := got.Runs[0].AutomationDetails.ID; id != "ipso/"+tc.name+"/" {
				t.Fatalf("category %q", id)
			}
			if results := got.Runs[0].Results; len(results) != 1 || results[0].Level != "error" {
				t.Fatalf("results %+v\nstdout %s\nstderr %s", results, stdout.String(), stderr.String())
			}
		})
	}
}

func TestSARIFNoChecksSelectedIsEmpty(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	withDir(t, root)
	writeRepoFile(t, root, ".ipso/build/manifest.json", `{"entries":[]}`)
	writeRepoFile(t, root, "plan.json", planBody)
	output := filepath.Join(root, "out.sarif")
	if _, stderr, code := planAt(t, now, []string{"plan.json", "--sarif", output}); code != 0 {
		t.Fatalf("code %d %s", code, stderr)
	}
	got, _ := readSARIF(t, output)
	if len(got.Runs[0].Results) != 0 {
		t.Fatalf("results %+v", got.Runs[0].Results)
	}
}

func TestSARIFRefusesAnOlderBuildOnlyWhenAsked(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	withDir(t, root)
	manifest := fmt.Sprintf(`{"entries":[{"decision_id":%q,"slug":"one","check_index":0,"engine":"opa","mode":"block","target":"terraform-plan","valid_from":"2026-01-01","valid_to":null,"env":null,"waivers":[],"compiler":"x","compiler_version":"1","artifacts":[]}]}`, idA)
	writeRepoFile(t, root, ".ipso/build/manifest.json", manifest)
	writeRepoFile(t, root, "plan.json", planBody)
	report := filepath.Join(root, "report.json")
	if _, stderr, _ := planAt(t, now, []string{"plan.json", "--report", report}); stderr != "" {
		t.Fatalf("a build without path must still evaluate: %s", stderr)
	}
	if err := os.Remove(report); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "out.sarif")
	_, stderr, code := planAt(t, now, []string{"plan.json", "--report", report, "--sarif", output})
	if code != 1 || !strings.Contains(stderr, "build-manifest") {
		t.Fatalf("code %d stderr %s", code, stderr)
	}
	for _, path := range []string{output, report} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s was written: %v", path, err)
		}
	}
}

func TestSARIFRefusesUnsafeManifestPath(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	withDir(t, root)
	manifest := fmt.Sprintf(`{"entries":[{"decision_id":%q,"slug":"one","path":"../outside.md","title":"One","check_index":0,"engine":"opa","mode":"block","target":"terraform-plan","valid_from":"2026-01-01","valid_to":null,"env":null,"waivers":[],"compiler":"x","compiler_version":"1","artifacts":[]}]}`, idA)
	writeRepoFile(t, root, ".ipso/build/manifest.json", manifest)
	writeRepoFile(t, root, "plan.json", planBody)
	_, stderr, code := planAt(t, now, []string{"plan.json"})
	if code != 1 || !strings.Contains(stderr, "build-manifest") {
		t.Fatalf("code %d stderr %s", code, stderr)
	}
}

func TestSARIFUsage(t *testing.T) {
	cases := [][]string{
		{"plan", "plan.json", "--sarif"},
		{"plan", "plan.json", "--sarif", ""},
		{"semgrep", ".", "--sarif", ""},
		{"checkov", "x.json", "--sarif", ""},
		{"plan", "plan.json", "--report", "same", "--sarif", mustAbs(t, "same")},
		{"plan", "plan.json", "--sarif", "a", "--sarif", "b"},
		{"plan", "plan.json", "--report", "same", "--sarif", "./same"},
		{"semgrep", ".", "--report", "same", "--sarif", "same"},
		{"checkov", "x.json", "--report", "same", "--sarif", "same"},
	}
	for _, args := range cases {
		var stdout, stderr strings.Builder
		if code := run(append([]string{"check"}, args...), &stdout, &stderr, deps{registry: builtin.Registry()}); code != 2 {
			t.Fatalf("%v: code %d %s", args, code, stderr.String())
		}
	}
}

func mustAbs(t *testing.T, path string) string {
	t.Helper()
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func TestExplainLinks(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	withDir(t, root)
	writeRepoFile(t, root, ".ipso/config.yaml", "decisions:\n  - docs/decisions/**/*.md\n")
	writeRepoFile(t, root, "docs/decisions/ebs.md", compileRecord(idA, "ebs-encrypted", "accepted", "blocking", "2026-01-01", "", ""))
	var stdout, stderr strings.Builder
	if code := run([]string{"explain", "ebs-encrypted"}, &stdout, &stderr, deps{now: func() time.Time { return now }, registry: builtin.Registry()}); code != 0 {
		t.Fatalf("code %d %s", code, stderr.String())
	}
	for _, want := range []string{"\nid: " + idA + "\n", "\npath: docs/decisions/ebs.md\n", "\nsources:\n  - pr https://github.com/acme/platform/pull/10\n"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("output %q lacks %q", stdout.String(), want)
		}
	}
}
