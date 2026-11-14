package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/builtin"
)

const planBody = `{"format_version":"1.2","resource_changes":[{"address":"aws_ebs_volume.data","mode":"managed","type":"aws_ebs_volume","change":{"actions":["create"],"after":{"encrypted":false},"after_unknown":{}}}]}`

func TestCheckPlan(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	withDir(t, root)
	record := compileRecord(idA, "ebs-encrypted", "accepted", "blocking", "2026-01-01", "", "  - engine: opa\n    target: terraform-plan\n    ref: ipso:aws/ebs-encrypted\n")
	writeRepoFile(t, root, "docs/decisions/ebs.md", record)
	writeRepoFile(t, root, "plan.json", planBody)
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", stderr)
	}

	report := filepath.Join(root, "report.json")
	stdout, stderr, code := planAt(t, now, []string{"plan.json", "--env", "prod", "--report", report})
	if code != 1 {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "ebs-encrypted: checks[0] (block): aws_ebs_volume.data: ") {
		t.Fatalf("stdout %s", stdout)
	}
	body, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if strings.Contains(text, "aws_ebs_volume") || strings.Contains(text, "false") {
		t.Fatalf("report carries plan contents: %s", text)
	}
	var decoded compiler.PlanReport
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ReportVersion != 2 || decoded.Env != "prod" || len(decoded.PlanSHA256) != 64 || len(decoded.BuildSHA256) != 64 {
		t.Fatalf("report %+v", decoded)
	}
	if len(decoded.Verdicts) != 1 || decoded.Verdicts[0].Result != "fail" || decoded.Verdicts[0].Violations != 1 {
		t.Fatalf("verdicts %+v", decoded.Verdicts)
	}
	info, err := os.Stat(report)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("report mode %o", info.Mode().Perm())
	}
}

func TestCheckPlanPass(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	withDir(t, root)
	record := compileRecord(idA, "ebs-encrypted", "accepted", "blocking", "2026-01-01", "", "  - engine: opa\n    target: terraform-plan\n    ref: ipso:aws/ebs-encrypted\n")
	writeRepoFile(t, root, "docs/decisions/ebs.md", record)
	passing := strings.Replace(planBody, `"encrypted":false`, `"encrypted":true`, 1)
	writeRepoFile(t, root, "plan.json", passing)
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", stderr)
	}
	stdout, stderr, code := planAt(t, now, []string{"--report", "report.json", "plan.json"})
	if code != 0 {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "ebs-encrypted: checks[0] (block): pass") {
		t.Fatalf("stdout %s", stdout)
	}
}

func TestCheckPlanNoBuild(t *testing.T) {
	root := t.TempDir()
	withDir(t, root)
	writeRepoFile(t, root, "plan.json", planBody)
	_, stderr, code := planAt(t, time.Now(), []string{"plan.json"})
	if code != 1 || !strings.Contains(stderr, "run ipso compile first") {
		t.Fatalf("code %d stderr %s", code, stderr)
	}
}

func TestCheckPlanNoneSelected(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	withDir(t, root)
	record := compileRecord(idA, "ebs-encrypted", "accepted", "blocking", "2026-01-01", "", "  - engine: opa\n    target: terraform-plan\n    ref: ipso:aws/ebs-encrypted\n")
	record = strings.Replace(record, "  - org: acme", "  - org: acme\n    env: [prod]", 1)
	writeRepoFile(t, root, "docs/decisions/ebs.md", record)
	writeRepoFile(t, root, "plan.json", planBody)
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", stderr)
	}
	stdout, stderr, code := planAt(t, now, []string{"plan.json", "--env", "dev"})
	if code != 0 {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "no checks selected") {
		t.Fatalf("stdout %s", stdout)
	}
}

func TestCheckPlanUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"check", "plan"}, &stdout, &stderr); code != 2 {
		t.Fatalf("code %d", code)
	}
	if code := Run([]string{"check", "other"}, &stdout, &stderr); code != 2 {
		t.Fatalf("code %d", code)
	}
}

func planAt(t *testing.T, now time.Time, args []string) (string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(append([]string{"check", "plan"}, args...), &stdout, &stderr, deps{now: func() time.Time { return now }, registry: builtin.Registry()})
	return stdout.String(), stderr.String(), code
}

func TestCheckPlanPrivacy(t *testing.T) {
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
	report := filepath.Join(root, "report.json")
	stdout, stderr, code := planAt(t, now, []string{"plan.json", "--report", report})
	if code != 1 {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, leaked := range []string{marker, "aws_ebs_volume", "false", "must"} {
		if strings.Contains(text, leaked) {
			t.Fatalf("report contains %q: %s", leaked, text)
		}
	}
	if !strings.Contains(stdout, marker) && !strings.Contains(stdout, "aws_ebs_volume.data") {
		t.Fatalf("stdout lost the finding: %s", stdout)
	}
}
