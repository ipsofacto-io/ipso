package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso/internal/baseline"
	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/builtin"
)

var baselineNow = time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)

const (
	baselinePlanCheck = "  - engine: opa\n    target: terraform-plan\n    ref: ipso:aws/ebs-encrypted\n"
	semgrepBlockCheck = "  - engine: semgrep\n    ref: rules/no-eval.yaml\n    mode: block\n"
	depcruiseCheck    = "  - engine: depcruise\n    target: typescript\n    ref: .dependency-cruiser.json\n    mode: block\n"
)

func baselineAt(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := run(append([]string{"baseline"}, args...), &stdout, &stderr, deps{now: func() time.Time { return baselineNow }, registry: builtin.Registry()})
	return stdout.String(), stderr.String(), code
}

func checkAt(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := run(append([]string{"check"}, args...), &stdout, &stderr, deps{now: func() time.Time { return baselineNow }, registry: builtin.Registry()})
	return stdout.String(), stderr.String(), code
}

func mustCompile(t *testing.T) string {
	t.Helper()
	stdout, stderr, code := compileAt(t, baselineNow, builtin.Registry())
	if code != 0 {
		t.Fatalf("compile %d\n%s\n%s", code, stdout, stderr)
	}
	return stdout
}

// baselineFlow creates a baseline for one subcommand, compiles, and checks that a re-run is waived.
func baselineFlow(t *testing.T, root, subcommand string, want int, args ...string) {
	t.Helper()
	stdout, stderr, code := baselineAt(t, append([]string{"create", subcommand}, args...)...)
	if code != 0 || !strings.Contains(stdout, "run ipso compile") {
		t.Fatalf("create %d\n%s\n%s", code, stdout, stderr)
	}
	file := readBaseline(t, root)
	if len(file.Checks) != 1 || len(file.Checks[0].Fingerprints) != want {
		t.Fatalf("file %+v, want %d fingerprints", file.Checks, want)
	}
	mustCompile(t)
	report := filepath.Join(root, "report.json")
	stdout, stderr, code = checkAt(t, append(append([]string{subcommand}, args...), "--report", report)...)
	if code != 0 || !strings.Contains(stdout, "waived (baseline: ") {
		t.Fatalf("check %d\n%s\n%s", code, stdout, stderr)
	}
	verdict := readVerdict(t, report)
	if verdict.Result != "waived" || verdict.Violations != want {
		t.Fatalf("verdict %+v", verdict)
	}
}

func readBaseline(t *testing.T, root string) baseline.File {
	t.Helper()
	file, found, err := baseline.Read(root)
	if err != nil || !found {
		t.Fatalf("baseline file: %v %v", found, err)
	}
	return file
}

func readVerdict(t *testing.T, path string) compiler.Verdict {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Verdicts []compiler.Verdict `json:"verdicts"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Verdicts) != 1 {
		t.Fatalf("verdicts %s", raw)
	}
	return decoded.Verdicts[0]
}

func planRepo(t *testing.T, checks string) string {
	t.Helper()
	root := t.TempDir()
	withDir(t, root)
	writeRepoFile(t, root, "docs/decisions/ebs.md", compileRecord(idA, "ebs-encrypted", "accepted", "blocking", "2026-01-01", "", checks))
	writeRepoFile(t, root, "plan.json", planBody)
	mustCompile(t)
	return root
}

// A second volume with a different address, so one plan is a superset of the baselined one.
func twoVolumes() string {
	second := `{"address":"aws_ebs_volume.logs","mode":"managed","type":"aws_ebs_volume","change":{"actions":["create"],"after":{"encrypted":false},"after_unknown":{}}}`
	return strings.Replace(planBody, `"resource_changes":[`, `"resource_changes":[`+second+`,`, 1)
}

func TestBaselinePlanFlow(t *testing.T) {
	root := planRepo(t, baselinePlanCheck)
	baselineFlow(t, root, "plan", 1, "plan.json")
}

func TestBaselineCheckovFlowSkipsNotReported(t *testing.T) {
	root := t.TempDir()
	withDir(t, root)
	writeRepoFile(t, root, "docs/decisions/port.md", compileRecord(idA, "admin-port", "accepted", "blocking", "2026-01-01", "", "  - engine: checkov\n    ref: CKV_AWS_24\n"))
	writeRepoFile(t, root, "results.json", `{"check_type":"terraform","results":{"passed_checks":[],"failed_checks":[{"check_id":"CKV_AWS_24","resource":"aws_sg.a","file_path":"/main.tf"}],"skipped_checks":[],"parsing_errors":[]}}`)
	mustCompile(t)
	baselineFlow(t, root, "checkov", 1, "results.json")

	// A missing control is not a pre-existing violation, so it cannot be recorded and stays a failure.
	if err := os.Remove(filepath.Join(root, baseline.RelPath)); err != nil {
		t.Fatal(err)
	}
	writeRepoFile(t, root, "results.json", `{"check_type":"terraform","results":{"passed_checks":[],"failed_checks":[],"skipped_checks":[],"parsing_errors":[]}}`)
	stdout, stderr, code := baselineAt(t, "create", "checkov", "results.json")
	if code != 0 || !strings.Contains(stdout, "recorded 0, skipped 1 that cannot be baselined") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	mustCompile(t)
	stdout, stderr, code = checkAt(t, "checkov", "results.json")
	if code != 1 || !strings.Contains(stdout, "check not reported") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestBaselineSemgrepFlow(t *testing.T) {
	root := semgrepRepo(t, baselineNow, semgrepBlockCheck, false)
	withSemgrep(t, "1.182.1", semgrepScan(semgrepHit, "1.182.1"))
	baselineFlow(t, root, "semgrep", 1, ".")
}

func TestBaselineDepcruiseFlow(t *testing.T) {
	root := cruiseRepo(t, baselineNow, depcruiseCheck, false)
	withDepcruise(t, "18.7.0", cruiseReport(cruiseHit, "18.7.0"))
	baselineFlow(t, root, "depcruise", 1, ".")
}

func TestBaselineArchunitRealFlow(t *testing.T) {
	jars := realArchUnitJars(t)
	root := archunitRepo(t, baselineNow, archunitCheck, false)
	compileBilling(t, root, "billing-violating")
	stdout, stderr, code := baselineAt(t, "create", "archunit", "target/classes", "--jars", jars)
	if code != 0 {
		t.Fatalf("create %d\n%s\n%s", code, stdout, stderr)
	}
	mustCompile(t)
	stdout, stderr, code = checkAt(t, "archunit", "target/classes", "--jars", jars)
	if code != 0 || !strings.Contains(stdout, "waived (baseline: ") {
		t.Fatalf("check %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestBaselineNewViolationFails(t *testing.T) {
	root := planRepo(t, baselinePlanCheck)
	if _, stderr, code := baselineAt(t, "create", "plan", "plan.json"); code != 0 {
		t.Fatal(stderr)
	}
	mustCompile(t)
	writeRepoFile(t, root, "plan.json", twoVolumes())
	report := filepath.Join(root, "report.json")
	stdout, stderr, code := planAt(t, baselineNow, []string{"plan.json", "--report", report})
	if code != 1 {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "aws_ebs_volume.logs") || strings.Contains(stdout, "aws_ebs_volume.data") || !strings.Contains(stdout, "baselined: 1") {
		t.Fatalf("stdout %s", stdout)
	}
	verdict := readVerdict(t, report)
	if verdict.Result != "fail" || verdict.Violations != 1 {
		t.Fatalf("verdict %+v", verdict)
	}
}

func TestBaselineNewViolationInWarnModeExitsZero(t *testing.T) {
	root := planRepo(t, baselinePlanCheck+"    mode: warn\n")
	if _, stderr, code := baselineAt(t, "create", "plan", "plan.json"); code != 0 {
		t.Fatal(stderr)
	}
	mustCompile(t)
	writeRepoFile(t, root, "plan.json", twoVolumes())
	stdout, stderr, code := planAt(t, baselineNow, []string{"plan.json"})
	if code != 0 || !strings.Contains(stdout, "aws_ebs_volume.logs") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestBaselineRepeatsWaiveAtMostTheirCount(t *testing.T) {
	root := semgrepRepo(t, baselineNow, semgrepBlockCheck, false)
	hit := func(lines ...string) string {
		items := make([]string, 0, len(lines))
		for _, line := range lines {
			items = append(items, `{"check_id":"no-eval","path":"a.py","start":{"line":`+line+`,"col":1},"end":{"line":`+line+`,"col":9},"extra":{"message":"m"}}`)
		}
		return "[" + strings.Join(items, ",") + "]"
	}
	withSemgrep(t, "1.182.1", semgrepScan(hit("3", "9"), "1.182.1"))
	if _, stderr, code := baselineAt(t, "create", "semgrep", "."); code != 0 {
		t.Fatal(stderr)
	}
	mustCompile(t)

	// Both findings moved, which is not a new violation.
	withSemgrep(t, "1.182.1", semgrepScan(hit("13", "19"), "1.182.1"))
	stdout, stderr, code := semgrepAt(t, baselineNow, []string{"."})
	if code != 0 || !strings.Contains(stdout, "waived (baseline: 2)") {
		t.Fatalf("moved %d\n%s\n%s", code, stdout, stderr)
	}

	withSemgrep(t, "1.182.1", semgrepScan(hit("3", "9", "20"), "1.182.1"))
	report := filepath.Join(root, "report.json")
	stdout, stderr, code = semgrepAt(t, baselineNow, []string{".", "--report", report})
	if code != 1 || !strings.Contains(stdout, "baselined: 2") {
		t.Fatalf("third repeat %d\n%s\n%s", code, stdout, stderr)
	}
	if verdict := readVerdict(t, report); verdict.Result != "fail" || verdict.Violations != 1 {
		t.Fatalf("verdict %+v", verdict)
	}
}

func TestBaselineErrorStaysAnError(t *testing.T) {
	semgrepRepo(t, baselineNow, semgrepBlockCheck, false)
	withSemgrep(t, "1.182.1", semgrepScan(semgrepHit, "1.182.1"))
	if _, stderr, code := baselineAt(t, "create", "semgrep", "."); code != 0 {
		t.Fatal(stderr)
	}
	mustCompile(t)
	withSemgrep(t, "0.0.1", semgrepScan(semgrepHit, "0.0.1"))
	stdout, stderr, code := semgrepAt(t, baselineNow, []string{"."})
	if code != 1 || !strings.Contains(stdout, "error: semgrep-version") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestBaselineWaiverStillCoversTheCheck(t *testing.T) {
	semgrepRepo(t, baselineNow, semgrepBlockCheck, true)
	withSemgrep(t, "1.182.1", semgrepScan(semgrepHit, "1.182.1"))
	if _, stderr, code := baselineAt(t, "create", "semgrep", "."); code != 0 {
		t.Fatal(stderr)
	}
	mustCompile(t)
	stdout, stderr, code := semgrepAt(t, baselineNow, []string{"."})
	if code != 0 || !strings.Contains(stdout, "(block): waived\n") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestBaselineCreateNeverAbsorbsNewViolations(t *testing.T) {
	root := planRepo(t, baselinePlanCheck)
	if _, stderr, code := baselineAt(t, "create", "plan", "plan.json"); code != 0 {
		t.Fatal(stderr)
	}
	before := readBaseline(t, root)
	writeRepoFile(t, root, "plan.json", twoVolumes())
	stdout, stderr, code := baselineAt(t, "create", "plan", "plan.json")
	if code != 0 || !strings.Contains(stdout, "already has a baseline") || !strings.Contains(stdout, "unchanged") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	after := readBaseline(t, root)
	if len(after.Checks[0].Fingerprints) != len(before.Checks[0].Fingerprints) || after.Salt != before.Salt {
		t.Fatalf("create changed the entry: %+v", after)
	}
}

func TestBaselineCleanCheckRecordsAnEmptyEntry(t *testing.T) {
	root := planRepo(t, baselinePlanCheck)
	writeRepoFile(t, root, "plan.json", strings.Replace(planBody, `"encrypted":false`, `"encrypted":true`, 1))
	stdout, stderr, code := baselineAt(t, "create", "plan", "plan.json")
	if code != 0 || !strings.Contains(stdout, "recorded 0") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	file := readBaseline(t, root)
	if len(file.Checks) != 1 || len(file.Checks[0].Fingerprints) != 0 {
		t.Fatalf("file %+v", file)
	}
	mustCompile(t)
	writeRepoFile(t, root, "plan.json", planBody)
	if stdout, stderr, code := planAt(t, baselineNow, []string{"plan.json"}); code != 1 {
		t.Fatalf("a violation after an empty baseline must fail: %d\n%s\n%s", code, stdout, stderr)
	}
	if stdout, _, code := baselineAt(t, "create", "plan", "plan.json"); code != 0 || !strings.Contains(stdout, "already has a baseline") {
		t.Fatalf("create absorbed a new violation: %s", stdout)
	}
}

func TestBaselineUpdateOnlyShrinks(t *testing.T) {
	root := planRepo(t, baselinePlanCheck)
	writeRepoFile(t, root, "plan.json", twoVolumes())
	if _, stderr, code := baselineAt(t, "create", "plan", "plan.json"); code != 0 {
		t.Fatal(stderr)
	}
	if got := len(readBaseline(t, root).Checks[0].Fingerprints); got != 2 {
		t.Fatalf("recorded %d", got)
	}

	// One volume is fixed.
	writeRepoFile(t, root, "plan.json", planBody)
	stdout, stderr, code := baselineAt(t, "update", "plan", "plan.json")
	if code != 0 || !strings.Contains(stdout, "removed 1, kept 1") {
		t.Fatalf("shrink %d\n%s\n%s", code, stdout, stderr)
	}
	if got := len(readBaseline(t, root).Checks[0].Fingerprints); got != 1 {
		t.Fatalf("kept %d", got)
	}

	// A new violation is never added.
	writeRepoFile(t, root, "plan.json", twoVolumes())
	stdout, stderr, code = baselineAt(t, "update", "plan", "plan.json")
	if code != 0 || !strings.Contains(stdout, "removed 0, kept 1") || !strings.Contains(stdout, "unchanged") {
		t.Fatalf("grow %d\n%s\n%s", code, stdout, stderr)
	}
	if got := len(readBaseline(t, root).Checks[0].Fingerprints); got != 1 {
		t.Fatalf("update added a fingerprint: %d", got)
	}
}

func TestBaselineUpdateLeavesOtherChecksAlone(t *testing.T) {
	root := planRepo(t, baselinePlanCheck)
	file, err := baseline.New()
	if err != nil {
		t.Fatal(err)
	}
	other := baseline.Check{DecisionID: "01HZZZZZZZZZZZZZZZZZZZZZZY", CheckIndex: 0, Fingerprints: []string{strings.Repeat("a", 64)}}
	file.Checks = append(file.Checks, other)
	raw, err := file.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	writeRepoFile(t, root, baseline.RelPath, string(raw))
	if _, stderr, code := baselineAt(t, "create", "plan", "plan.json"); code != 0 {
		t.Fatal(stderr)
	}
	writeRepoFile(t, root, "plan.json", strings.Replace(planBody, `"encrypted":false`, `"encrypted":true`, 1))
	if _, stderr, code := baselineAt(t, "update", "plan", "plan.json"); code != 0 {
		t.Fatal(stderr)
	}
	got := readBaseline(t, root)
	kept := got.Find(other.DecisionID, 0, baseline.Scope{})
	if kept < 0 || len(got.Checks[kept].Fingerprints) != 1 {
		t.Fatalf("file %+v", got)
	}
	mine := got.Find(idA, 0, baseline.Scope{})
	if mine < 0 || len(got.Checks[mine].Fingerprints) != 0 {
		t.Fatalf("file %+v", got)
	}
}

func TestBaselineErrorWritesNothing(t *testing.T) {
	root := semgrepRepo(t, baselineNow, semgrepBlockCheck, false)
	withSemgrep(t, "0.0.1", semgrepScan(semgrepHit, "0.0.1"))
	_, stderr, code := baselineAt(t, "create", "semgrep", ".")
	if code != 1 || !strings.Contains(stderr, "nothing written") {
		t.Fatalf("code %d %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(root, baseline.RelPath)); !os.IsNotExist(err) {
		t.Fatalf("file written: %v", err)
	}
}

func TestBaselineUpdateNeedsAFile(t *testing.T) {
	planRepo(t, baselinePlanCheck)
	_, stderr, code := baselineAt(t, "update", "plan", "plan.json")
	if code != 1 || !strings.Contains(stderr, "ipso baseline create") {
		t.Fatalf("code %d %s", code, stderr)
	}
}

func TestBaselineNeedsABuild(t *testing.T) {
	root := t.TempDir()
	withDir(t, root)
	writeRepoFile(t, root, "plan.json", planBody)
	_, stderr, code := baselineAt(t, "create", "plan", "plan.json")
	if code != 1 || !strings.Contains(stderr, "build-missing") {
		t.Fatalf("code %d %s", code, stderr)
	}
}

func TestBaselineNoChecksSelected(t *testing.T) {
	root := planRepo(t, "")
	stdout, stderr, code := baselineAt(t, "create", "plan", "plan.json")
	if code != 0 || !strings.Contains(stdout, "no checks selected") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(root, baseline.RelPath)); !os.IsNotExist(err) {
		t.Fatalf("file written: %v", err)
	}
}

func TestBaselineUsage(t *testing.T) {
	planRepo(t, baselinePlanCheck)
	for _, args := range [][]string{
		{},
		{"create"},
		{"delete", "plan", "plan.json"},
		{"create", "ci", "evidence.json", "--sha", strings.Repeat("a", 40)},
		{"create", "bogus"},
		{"create", "plan"},
		{"create", "plan", "plan.json", "--report", "r.json"},
		{"create", "plan", "plan.json", "--sarif", "r.sarif"},
		{"update", "plan", "plan.json", "--bundle", "b", "--digest", "sha256:x", "--key", "k"},
	} {
		_, stderr, code := baselineAt(t, args...)
		if code != 2 || !strings.Contains(stderr, "ipso baseline create|update") {
			t.Fatalf("args %q code %d stderr %q", args, code, stderr)
		}
	}
}

func TestBaselinePrivacy(t *testing.T) {
	marker := "secret-bucket-name-9f3a"
	root := planRepo(t, baselinePlanCheck)
	writeRepoFile(t, root, "plan.json", strings.ReplaceAll(planBody, "aws_ebs_volume.data", "aws_ebs_volume."+marker))
	stdout, stderr, code := baselineAt(t, "create", "plan", "plan.json")
	if code != 0 || strings.Contains(stdout, marker) || strings.Contains(stderr, marker) {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	salt := readBaseline(t, root).Salt
	mustCompile(t)
	report := filepath.Join(root, "report.json")
	output := filepath.Join(root, "out.sarif")
	if _, stderr, code := planAt(t, baselineNow, []string{"plan.json", "--report", report, "--sarif", output}); code != 0 {
		t.Fatal(stderr)
	}
	for _, path := range []string{filepath.Join(root, baseline.RelPath), report, output} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), marker) {
			t.Fatalf("%s holds the marker: %s", path, raw)
		}
		if path != filepath.Join(root, baseline.RelPath) && strings.Contains(string(raw), salt) {
			t.Fatalf("%s holds the salt: %s", path, raw)
		}
	}
}

func TestBaselineReportShapeIsUnchanged(t *testing.T) {
	root := planRepo(t, baselinePlanCheck)
	if _, stderr, code := baselineAt(t, "create", "plan", "plan.json"); code != 0 {
		t.Fatal(stderr)
	}
	mustCompile(t)
	report := filepath.Join(root, "report.json")
	if _, stderr, code := planAt(t, baselineNow, []string{"plan.json", "--report", report}); code != 0 {
		t.Fatal(stderr)
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["report_version"] != float64(1) {
		t.Fatalf("report %s", raw)
	}
	verdict := decoded["verdicts"].([]any)[0].(map[string]any)
	if len(verdict) != 6 {
		t.Fatalf("verdict fields %v", verdict)
	}
}

func TestBaselineSARIFMarksCoveredResults(t *testing.T) {
	root := semgrepRepo(t, baselineNow, semgrepBlockCheck, false)
	withSemgrep(t, "1.182.1", semgrepScan(semgrepHit, "1.182.1"))
	if _, stderr, code := baselineAt(t, "create", "semgrep", "."); code != 0 {
		t.Fatal(stderr)
	}
	mustCompile(t)
	output := filepath.Join(root, "out.sarif")
	if _, stderr, code := semgrepAt(t, baselineNow, []string{".", "--sarif", output}); code != 0 {
		t.Fatal(stderr)
	}
	got, _ := readSARIF(t, output)
	result := got.Runs[0].Results[0]
	if result.Level != "note" || !strings.HasPrefix(result.Message.Text, "Baselined: ") || len(result.Suppressions) != 1 {
		t.Fatalf("result %+v", result)
	}
}

func TestCompileStampsTheBaseline(t *testing.T) {
	root := planRepo(t, baselinePlanCheck)
	if _, stderr, code := baselineAt(t, "create", "plan", "plan.json"); code != 0 {
		t.Fatal(stderr)
	}
	file := readBaseline(t, root)
	file.Checks = append(file.Checks, baseline.Check{DecisionID: "01HZZZZZZZZZZZZZZZZZZZZZZY", CheckIndex: 4, Fingerprints: []string{}})
	raw, err := file.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	writeRepoFile(t, root, baseline.RelPath, string(raw))
	stdout := mustCompile(t)
	if !strings.Contains(stdout, "01HZZZZZZZZZZZZZZZZZZZZZZY checks[4] has no compiled check, ignored") {
		t.Fatalf("stdout %s", stdout)
	}
	build, err := compiler.LoadBuild(root)
	if err != nil {
		t.Fatal(err)
	}
	stamped := build.Entries[0].Baseline
	if stamped == nil || stamped.Salt != file.Salt || len(stamped.Fingerprints) != 1 {
		t.Fatalf("entry %+v", build.Entries[0])
	}
}

func TestCompileRefusesABadBaselineFile(t *testing.T) {
	root := planRepo(t, baselinePlanCheck)
	writeRepoFile(t, root, baseline.RelPath, `{"baseline_version":9}`)
	_, stderr, code := compileAt(t, baselineNow, builtin.Registry())
	if code != 1 || !strings.Contains(stderr, baseline.CodeFile) {
		t.Fatalf("code %d %s", code, stderr)
	}
}

func TestBadManifestBaselineIsRefused(t *testing.T) {
	good := strings.Repeat("a", 64)
	for name, field := range map[string]string{
		"short salt":    `{"salt":"ab","fingerprints":[]}`,
		"bad digest":    `{"salt":"` + good + `","fingerprints":["zz"]}`,
		"repeated hash": `{"salt":"` + good + `","fingerprints":["` + good + `","` + good + `"]}`,
	} {
		root := t.TempDir()
		withDir(t, root)
		writeRepoFile(t, root, ".ipso/build/manifest.json", `{"entries":[{"decision_id":"`+idA+`","slug":"one","check_index":0,"engine":"opa","mode":"block","target":"terraform-plan","valid_from":"2026-01-01","valid_to":null,"env":null,"waivers":[],"compiler":"x","compiler_version":"1","artifacts":[],"baseline":`+field+`}]}`)
		writeRepoFile(t, root, "plan.json", planBody)
		_, stderr, code := planAt(t, baselineNow, []string{"plan.json"})
		if code != 1 || !strings.Contains(stderr, "build-manifest") {
			t.Fatalf("%s: code %d %s", name, code, stderr)
		}
	}
}

// A signed bundle pins the baseline it was packed with, so editing the file afterwards changes nothing.
func TestSignedBundleHonorsTheStampedBaseline(t *testing.T) {
	root := planRepo(t, baselinePlanCheck)
	if _, stderr, code := baselineAt(t, "create", "plan", "plan.json"); code != 0 {
		t.Fatal(stderr)
	}
	mustCompile(t)
	layout := filepath.Join(root, "layout")
	priv, pub := cliKeys(t)
	stdout, stderr, code := runAt(t, []string{"bundle", "pack", "--layout", layout})
	if code != 0 {
		t.Fatalf("pack %d\n%s\n%s", code, stdout, stderr)
	}
	digest := strings.TrimSpace(stdout)
	if stdout, stderr, code := runAt(t, []string{"bundle", "sign", "--layout", layout, "--key", priv}); code != 0 {
		t.Fatalf("sign %d\n%s\n%s", code, stdout, stderr)
	}
	args := []string{"plan.json", "--bundle", layout, "--digest", digest, "--key", pub}
	stdout, stderr, code = planAt(t, baselineNow, args)
	if code != 0 || !strings.Contains(stdout, "waived (baseline: 1)") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}

	// Trimming the file cannot change what the signed bundle covers, and neither can adding to it.
	file := readBaseline(t, root)
	file.Checks[0].Fingerprints = []string{}
	raw, err := file.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	writeRepoFile(t, root, baseline.RelPath, string(raw))
	stdout, stderr, code = planAt(t, baselineNow, args)
	if code != 0 || !strings.Contains(stdout, "waived (baseline: 1)") {
		t.Fatalf("after edit %d\n%s\n%s", code, stdout, stderr)
	}
	writeRepoFile(t, root, "plan.json", twoVolumes())
	if stdout, stderr, code = planAt(t, baselineNow, args); code != 1 || !strings.Contains(stdout, "aws_ebs_volume.logs") {
		t.Fatalf("new violation %d\n%s\n%s", code, stdout, stderr)
	}
}

// A manifest with a large baseline is over the 1 MiB artifact cap and must still pack and verify.
func TestSignedBundleCarriesALargeBaseline(t *testing.T) {
	root := planRepo(t, baselinePlanCheck)
	if _, stderr, code := baselineAt(t, "create", "plan", "plan.json"); code != 0 {
		t.Fatal(stderr)
	}
	file := readBaseline(t, root)
	for i := range 20000 {
		file.Checks[0].Fingerprints = append(file.Checks[0].Fingerprints, fmt.Sprintf("%064x", i))
	}
	raw, err := file.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	writeRepoFile(t, root, baseline.RelPath, string(raw))
	mustCompile(t)
	manifest, err := os.Stat(filepath.Join(root, ".ipso", "build", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Size() <= compiler.MaxRefBytes {
		t.Fatalf("manifest is only %d bytes", manifest.Size())
	}
	layout := filepath.Join(root, "layout")
	priv, pub := cliKeys(t)
	stdout, stderr, code := runAt(t, []string{"bundle", "pack", "--layout", layout})
	if code != 0 {
		t.Fatalf("pack %d\n%s\n%s", code, stdout, stderr)
	}
	digest := strings.TrimSpace(stdout)
	if stdout, stderr, code := runAt(t, []string{"bundle", "sign", "--layout", layout, "--key", priv}); code != 0 {
		t.Fatalf("sign %d\n%s\n%s", code, stdout, stderr)
	}
	stdout, stderr, code = planAt(t, baselineNow, []string{"plan.json", "--bundle", layout, "--digest", digest, "--key", pub})
	if code != 0 || !strings.Contains(stdout, "waived (baseline: 1)") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestSameInputCannotExtendABaseline(t *testing.T) {
	root := planRepo(t, baselinePlanCheck)
	if _, stderr, code := baselineAt(t, "create", "plan", "plan.json"); code != 0 {
		t.Fatal(stderr)
	}
	writeRepoFile(t, root, "other.json", otherPlan())
	stdout, stderr, code := baselineAt(t, "create", "plan", "other.json")
	if code != 0 || !strings.Contains(stdout, "already has a baseline for this env and input, name another with --env or --input") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	mustCompile(t)
	if stdout, stderr, code := planAt(t, baselineNow, []string{"other.json"}); code != 1 {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
}

func otherPlan() string {
	return strings.ReplaceAll(planBody, "aws_ebs_volume.data", "aws_ebs_volume.other")
}

func TestBaselineSeveralEnvironments(t *testing.T) {
	root := planRepo(t, baselinePlanCheck)
	writeRepoFile(t, root, "prod.json", planBody)
	writeRepoFile(t, root, "staging.json", otherPlan())
	for _, args := range [][]string{{"prod.json", "--env", "prod"}, {"staging.json", "--env", "staging"}} {
		if stdout, stderr, code := baselineAt(t, append([]string{"create", "plan"}, args...)...); code != 0 || !strings.Contains(stdout, "recorded 1") {
			t.Fatalf("create %v: %d\n%s\n%s", args, code, stdout, stderr)
		}
	}
	file := readBaseline(t, root)
	if len(file.Checks) != 2 || file.Checks[0].Env != "prod" || file.Checks[1].Env != "staging" {
		t.Fatalf("file %+v", file)
	}
	mustCompile(t)
	for _, args := range [][]string{{"prod.json", "--env", "prod"}, {"staging.json", "--env", "staging"}} {
		if stdout, stderr, code := planAt(t, baselineNow, args); code != 0 || !strings.Contains(stdout, "waived (baseline: 1)") {
			t.Fatalf("check %v: %d\n%s\n%s", args, code, stdout, stderr)
		}
	}

	// A baseline never crosses inputs, even for the same address, and a run with no name matches nothing.
	for _, args := range [][]string{{"prod.json", "--env", "staging"}, {"prod.json"}, {"prod.json", "--env", "prod", "--input", "a"}} {
		if stdout, stderr, code := planAt(t, baselineNow, args); code != 1 || strings.Contains(stdout, "baseline") {
			t.Fatalf("check %v: %d\n%s\n%s", args, code, stdout, stderr)
		}
	}

	// update touches only its own env and input.
	writeRepoFile(t, root, "prod.json", strings.Replace(planBody, `"encrypted":false`, `"encrypted":true`, 1))
	stdout, stderr, code := baselineAt(t, "update", "plan", "prod.json", "--env", "prod")
	if code != 0 || !strings.Contains(stdout, "removed 1, kept 0") {
		t.Fatalf("update %d\n%s\n%s", code, stdout, stderr)
	}
	file = readBaseline(t, root)
	if len(file.Checks[0].Fingerprints) != 0 || len(file.Checks[1].Fingerprints) != 1 {
		t.Fatalf("file %+v", file)
	}

	stdout, _, code = baselineAt(t, "update", "plan", "prod.json", "--env", "dev")
	if code != 0 || !strings.Contains(stdout, "no baseline for this env and input") {
		t.Fatalf("update %d\n%s", code, stdout)
	}
}

func TestBaselineSplitRunsWithInputNames(t *testing.T) {
	root := semgrepRepo(t, baselineNow, semgrepBlockCheck, false)
	scan := func(file string) string {
		return semgrepScan(`[{"check_id":"no-eval","path":"`+file+`","start":{"line":3,"col":1},"end":{"line":3,"col":9},"extra":{"message":"m"}}]`, "1.182.1")
	}
	withSemgrep(t, "1.182.1", scan("services/a/x.py"))
	if stdout, stderr, code := baselineAt(t, "create", "semgrep", "services/a", "--input", "service-a"); code != 0 {
		t.Fatalf("create %d\n%s\n%s", code, stdout, stderr)
	}
	withSemgrep(t, "1.182.1", scan("services/b/y.py"))
	if stdout, stderr, code := baselineAt(t, "create", "semgrep", "services/b", "--input", "service-b"); code != 0 {
		t.Fatalf("create %d\n%s\n%s", code, stdout, stderr)
	}
	mustCompile(t)
	stdout, stderr, code := semgrepAt(t, baselineNow, []string{"services/b", "--input", "service-b"})
	if code != 0 || !strings.Contains(stdout, "waived (baseline: 1)") {
		t.Fatalf("service-b %d\n%s\n%s", code, stdout, stderr)
	}
	withSemgrep(t, "1.182.1", scan("services/a/x.py"))
	output := filepath.Join(root, "out.sarif")
	stdout, stderr, code = semgrepAt(t, baselineNow, []string{"services/a", "--input", "service-a", "--sarif", output})
	if code != 0 || !strings.Contains(stdout, "waived (baseline: 1)") {
		t.Fatalf("service-a %d\n%s\n%s", code, stdout, stderr)
	}
	got, _ := readSARIF(t, output)
	if id := got.Runs[0].AutomationDetails.ID; id != "ipso/semgrep/-/service-a/" {
		t.Fatalf("category %q", id)
	}
}

func TestCompileStampsEveryScopeOfACheck(t *testing.T) {
	root := planRepo(t, baselinePlanCheck)
	writeRepoFile(t, root, "other.json", otherPlan())
	for _, args := range [][]string{{"plan.json", "--env", "prod"}, {"other.json", "--input", "stack-a"}} {
		if _, stderr, code := baselineAt(t, append([]string{"create", "plan"}, args...)...); code != 0 {
			t.Fatal(stderr)
		}
	}
	mustCompile(t)
	build, err := compiler.LoadBuild(root)
	if err != nil {
		t.Fatal(err)
	}
	stamped := build.Entries[0].Baseline
	if stamped == nil || len(stamped.Fingerprints) != 2 || stamped.Fingerprints[0] >= stamped.Fingerprints[1] {
		t.Fatalf("entry %+v", build.Entries[0])
	}
}

func TestInputNameUsage(t *testing.T) {
	planRepo(t, baselinePlanCheck)
	for _, args := range [][]string{
		{"plan", "plan.json", "--input"},
		{"plan", "plan.json", "--input", ""},
		{"plan", "plan.json", "--input", "a/b"},
		{"plan", "plan.json", "--input", "a", "--input", "b"},
		{"semgrep", ".", "--input", "a b"},
		{"checkov", "x.json", "--input", "-a"},
		{"ci", "x.json", "--sha", strings.Repeat("a", 40), "--input", "a"},
	} {
		if _, stderr, code := checkAt(t, args...); code != 2 || !strings.Contains(stderr, "usage:") {
			t.Fatalf("args %q code %d stderr %q", args, code, stderr)
		}
	}
}

func TestSARIFCategoryNamesTheInput(t *testing.T) {
	root := planRepo(t, baselinePlanCheck)
	output := filepath.Join(root, "out.sarif")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "ipso/plan/"},
		{[]string{"--env", "prod"}, "ipso/plan/prod/"},
		{[]string{"--input", "stack-a"}, "ipso/plan/-/stack-a/"},
		{[]string{"--env", "prod", "--input", "stack-a"}, "ipso/plan/prod/stack-a/"},
	} {
		if _, stderr, code := planAt(t, baselineNow, append([]string{"plan.json", "--sarif", output}, tc.args...)); code != 1 {
			t.Fatalf("%v: code %d %s", tc.args, code, stderr)
		}
		got, _ := readSARIF(t, output)
		if id := got.Runs[0].AutomationDetails.ID; id != tc.want {
			t.Fatalf("%v: category %q", tc.args, id)
		}
	}
}
