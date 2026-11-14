package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/builtin"
)

const semgrepRule = `rules:
  - id: no-eval
    languages:
      - python
    message: Do not eval
    pattern: eval(...)
`

func TestCheckSemgrep(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	semgrepRepo(t, now, "  - engine: semgrep\n    ref: rules/no-eval.yaml\n    mode: block\n", false)
	withSemgrep(t, "1.182.1", semgrepScan("[]", "1.182.1"))
	stdout, stderr, code := semgrepAt(t, now, []string{"."})
	if code != 0 || !strings.Contains(stdout, "scan: checks[0] (block): pass") {
		t.Fatalf("dot code %d\n%s\n%s", code, stdout, stderr)
	}

	withSemgrep(t, "1.182.1", semgrepScan(semgrepHit, "1.182.1"))
	stdout, stderr, code = semgrepAt(t, now, []string{"src"})
	if code != 1 || !strings.Contains(stdout, "no-eval secret.py:3") {
		t.Fatalf("fail code %d\n%s\n%s", code, stdout, stderr)
	}

	semgrepRepo(t, now, "  - engine: semgrep\n    ref: rules/no-eval.yaml\n    mode: warn\n", false)
	withSemgrep(t, "1.182.1", semgrepScan(semgrepHit, "1.182.1"))
	stdout, _, code = semgrepAt(t, now, []string{"src"})
	if code != 0 || !strings.Contains(stdout, "(warn): no-eval") {
		t.Fatalf("warn code %d\n%s", code, stdout)
	}
}

func TestCheckSemgrepSharesScan(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	checks := "  - engine: semgrep\n    ref: rules/no-eval.yaml\n    mode: block\n  - engine: semgrep\n    ref: rules/no-eval.yaml\n    mode: block\n"
	semgrepRepo(t, now, checks, false)
	withSemgrep(t, "1.182.1", semgrepScan("[]", "1.182.1"))
	count := filepath.Join(t.TempDir(), "count")
	t.Setenv("FAKE_SEMGREP_COUNT", count)
	stdout, stderr, code := semgrepAt(t, now, []string{"src"})
	if code != 0 || strings.Count(stdout, "pass") != 2 {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	if got := strings.Count(readCount(t, count), "x"); got != 1 {
		t.Fatalf("scans %d", got)
	}
}

func TestCheckSemgrepWaiver(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	semgrepRepo(t, now, "  - engine: semgrep\n    ref: rules/no-eval.yaml\n    mode: block\n", true)
	withSemgrep(t, "1.182.1", semgrepScan(semgrepHit, "1.182.1"))
	stdout, stderr, code := semgrepAt(t, now, []string{"src"})
	if code != 0 || !strings.Contains(stdout, "waived") {
		t.Fatalf("waiver code %d\n%s\n%s", code, stdout, stderr)
	}

	t.Setenv("PATH", t.TempDir())
	stdout, stderr, code = semgrepAt(t, now, []string{"src"})
	if code != 1 || !strings.Contains(stdout, "semgrep-missing") || strings.Contains(stdout, "waived") {
		t.Fatalf("missing waiver code %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestCheckSemgrepReport(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := semgrepRepo(t, now, "  - engine: semgrep\n    ref: rules/no-eval.yaml\n    mode: block\n", false)
	record := compileRecord(idA, "scan", "accepted", "blocking", "2026-01-01", "", "  - engine: semgrep\n    ref: rules/no-eval.yaml\n    mode: block\n")
	record = strings.Replace(record, "  - org: acme\n", "  - org: acme\n    env: [prod]\n", 1)
	writeRepoFile(t, root, "docs/decisions/boundary.md", record)
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile env: %s", stderr)
	}
	withSemgrep(t, "1.182.1", semgrepScan(semgrepHit, "1.182.1"))

	none := filepath.Join(root, "none.json")
	stdout, stderr, code := semgrepAt(t, now, []string{"src", "--env", "dev", "--report", none})
	if code != 0 || !strings.Contains(stdout, "no checks selected") {
		t.Fatalf("env code %d\n%s\n%s", code, stdout, stderr)
	}
	noneBody, err := os.ReadFile(none)
	if err != nil {
		t.Fatal(err)
	}
	var empty compiler.SemgrepReport
	if err := json.Unmarshal(noneBody, &empty); err != nil {
		t.Fatal(err)
	}
	if empty.SemgrepVersion != "" || len(empty.Verdicts) != 0 || len(empty.Paths) != 1 || empty.Paths[0] != "src" {
		t.Fatalf("empty report %+v", empty)
	}

	report := filepath.Join(root, "report.json")
	stdout, stderr, code = semgrepAt(t, now, []string{"src", "--env", "prod", "--report", report})
	if code != 1 || !strings.Contains(stdout, "secret.py") {
		t.Fatalf("report code %d\n%s\n%s", code, stdout, stderr)
	}
	body, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if strings.Contains(text, "secret.py") || strings.Contains(text, "no-eval") || strings.Contains(text, "secret message") {
		t.Fatalf("report carries the finding: %s", text)
	}
	var decoded compiler.SemgrepReport
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ReportVersion != 2 || decoded.Env != "prod" || len(decoded.Paths) != 1 || decoded.Paths[0] != "src" || decoded.SemgrepVersion != "1.182.1" || len(decoded.BuildSHA256) != 64 {
		t.Fatalf("report %+v", decoded)
	}
	if len(decoded.Verdicts) != 1 || decoded.Verdicts[0].Result != "fail" || decoded.Verdicts[0].Violations != 1 {
		t.Fatalf("verdicts %+v", decoded.Verdicts)
	}
	info, err := os.Stat(report)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", info, err)
	}
}

func TestCheckSemgrepVersion(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	semgrepRepo(t, now, "  - engine: semgrep\n    ref: rules/no-eval.yaml\n    mode: block\n", false)
	withSemgrep(t, "1.183.0", semgrepScan(semgrepHit, "1.183.0"))
	stdout, stderr, code := semgrepAt(t, now, []string{"src"})
	if code != 1 || !strings.Contains(stdout, "semgrep-version") {
		t.Fatalf("version code %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestCheckSemgrepUsage(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	for _, args := range [][]string{{}, {"../x"}, {"/abs"}, {"src/*"}, {"src/../x"}, {"--config"}, {"src", "--env"}, {"src", "--bogus"}} {
		_, stderr, code := semgrepAt(t, now, args)
		if code != 2 {
			t.Fatalf("args %q code %d stderr %s", args, code, stderr)
		}
	}
}

func semgrepRepo(t *testing.T, now time.Time, checks string, waiver bool) string {
	t.Helper()
	root := t.TempDir()
	withDir(t, root)
	record := compileRecord(idA, "scan", "accepted", "blocking", "2026-01-01", "", checks)
	if waiver {
		record = strings.Replace(record, "\nwaivers: []\n", "\nwaivers:\n  - reason: cutover\n    approver: Ada Lovelace\n    valid_from: 2026-01-01\n    valid_to: 2026-03-01\n", 1)
	}
	writeRepoFile(t, root, "docs/decisions/boundary.md", record)
	writeRepoFile(t, root, "rules/no-eval.yaml", semgrepRule)
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", stderr)
	}
	return root
}

func withSemgrep(t *testing.T, version, stdout string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake semgrep is a shell script")
	}
	dir := t.TempDir()
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then
  printf '%s\n' "$FAKE_SEMGREP_VERSION"
  exit 0
fi
if [ -n "$FAKE_SEMGREP_COUNT" ]; then
  printf 'x\n' >> "$FAKE_SEMGREP_COUNT"
fi
printf '%s' "$FAKE_SEMGREP_STDOUT"
`
	if err := os.WriteFile(filepath.Join(dir, "semgrep"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("FAKE_SEMGREP_VERSION", version)
	t.Setenv("FAKE_SEMGREP_STDOUT", stdout)
}

func semgrepAt(t *testing.T, now time.Time, args []string) (string, string, int) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := run(append([]string{"check", "semgrep"}, args...), &stdout, &stderr, deps{now: func() time.Time { return now }, registry: builtin.Registry()})
	return stdout.String(), stderr.String(), code
}

func semgrepScan(results, version string) string {
	return `{"version":"` + version + `","results":` + results + `,"errors":[],"paths":{"scanned":["secret.py"]},"skipped_rules":[]}`
}

const semgrepHit = `[{"check_id":"no-eval","path":"secret.py","start":{"line":3},"extra":{"message":"secret message"}}]`
