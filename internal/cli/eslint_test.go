package cli

import (
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/builtin"
)

const (
	eslintTSCheck = "  - engine: eslint\n    target: typescript\n    ref: eslint-ts.json\n    mode: block\n"
	eslintJSCheck = "  - engine: eslint\n    target: javascript\n    ref: eslint-js.json\n    mode: block\n"
)

// eslintTestdata is the ESLint compiler's testdata. It is anchored to this file because tests change directory.
func eslintTestdata() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "compiler", "eslint", "testdata")
}

// copyESLintSubject writes the repository of one fixture subject into root. A .fixture suffix is dropped.
func copyESLintSubject(t *testing.T, root, subject string) {
	t.Helper()
	src := filepath.Join(eslintTestdata(), subject, "repo")
	err := filepath.WalkDir(src, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		writeRepoFile(t, root, filepath.ToSlash(strings.TrimSuffix(rel, ".fixture")), string(raw))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// eslintRepo writes one in-force decision with the given checks over one fixture subject, and compiles it.
func eslintRepo(t *testing.T, now time.Time, checks string, waiver bool, subject string) string {
	t.Helper()
	root := t.TempDir()
	withDir(t, root)
	record := compileRecord(idA, "app", "accepted", "blocking", "2026-01-01", "", checks)
	if waiver {
		record = strings.Replace(record, "\nwaivers: []\n", "\nwaivers:\n  - reason: cutover\n    approver: Ada Lovelace\n    valid_from: 2026-01-01\n    valid_to: 2026-03-01\n", 1)
	}
	writeRepoFile(t, root, "docs/decisions/app.md", record)
	copyESLintSubject(t, root, subject)
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", stderr)
	}
	return root
}

func eslintAt(t *testing.T, now time.Time, args []string) (string, string, int) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := run(append([]string{"check", "eslint"}, args...), &stdout, &stderr, deps{now: func() time.Time { return now }, registry: builtin.Registry()})
	return stdout.String(), stderr.String(), code
}

func readESLintReport(t *testing.T, path string) (compiler.ESLintReport, string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded compiler.ESLintReport
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded, string(body)
}

func TestCheckESLintUsage(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	for _, args := range [][]string{
		{},
		{"--env", "prod"},
		{"--report", "out.json"},
		{"services", "--jars", "lib"},
		{"../x"},
		{"/abs"},
		{"services/*"},
		{"-x"},
		{"services", "--env"},
		{"services", "--env", "--report", "out.json"},
		{"services", "--report"},
		{"services", "--env", "prod", "--env", "dev"},
		{"services", "--bogus"},
	} {
		stdout, stderr, code := eslintAt(t, now, args)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "usage: ipso check eslint") {
			t.Fatalf("args %q code %d stdout %q stderr %q", args, code, stdout, stderr)
		}
	}
}

func TestCheckUsageListsESLint(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := run([]string{"check", "bogus"}, &stdout, &stderr, deps{registry: builtin.Registry()}); code != 2 || !strings.Contains(stderr.String(), eslintUsage) {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	stdout.Reset()
	if code := run([]string{"help"}, &stdout, &stderr, deps{registry: builtin.Registry()}); code != 0 || !strings.Contains(stdout.String(), "ipso check eslint <path>...") {
		t.Fatalf("code %d stdout %s", code, stdout.String())
	}
}

func TestCheckESLintNeedsABuild(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	withDir(t, t.TempDir())
	_, stderr, code := eslintAt(t, now, []string{"services"})
	if code != 1 || !strings.Contains(stderr, "build-missing") {
		t.Fatalf("code %d stderr %s", code, stderr)
	}
}

func TestCheckESLintSelectsNothing(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := eslintRepo(t, now, eslintTSCheck, false, "app-clean")
	record := compileRecord(idA, "app", "accepted", "blocking", "2026-01-01", "", eslintTSCheck)
	record = strings.Replace(record, "  - org: acme\n", "  - org: acme\n    env: [prod]\n", 1)
	writeRepoFile(t, root, "docs/decisions/app.md", record)
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", stderr)
	}
	// Neither eslint nor the paths are needed when nothing is selected.
	t.Setenv("PATH", t.TempDir())
	report := filepath.Join(root, "none.json")
	stdout, stderr, code := eslintAt(t, now, []string{"missing", "--env", "dev", "--report", report})
	if code != 0 || !strings.Contains(stdout, "no checks selected") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	decoded, _ := readESLintReport(t, report)
	if decoded.ESLintVersion != "" || len(decoded.Verdicts) != 0 || len(decoded.Paths) != 1 || decoded.Paths[0] != "missing" || decoded.Env != "dev" {
		t.Fatalf("report %+v", decoded)
	}
}

func TestCheckESLintIgnoresOtherChecks(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	checks := eslintTSCheck + "  - engine: ci-binding\n    job: build\n"
	root := eslintRepo(t, now, checks, false, "app-clean")
	t.Setenv("PATH", t.TempDir())
	report := filepath.Join(root, "report.json")
	stdout, _, code := eslintAt(t, now, []string{"services", "--report", report})
	if code != 1 || strings.Count(stdout, "eslint-missing") != 1 || strings.Contains(stdout, "checks[1]") {
		t.Fatalf("code %d\n%s", code, stdout)
	}
	decoded, _ := readESLintReport(t, report)
	if len(decoded.Verdicts) != 1 || decoded.Verdicts[0].CheckIndex != 0 {
		t.Fatalf("verdicts %+v", decoded.Verdicts)
	}
}

func TestCheckESLintMissingBinaryIsAnErrorEvenWithAWaiver(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := eslintRepo(t, now, eslintTSCheck, true, "app-violating")
	t.Setenv("PATH", t.TempDir())
	report := filepath.Join(root, "report.json")
	stdout, stderr, code := eslintAt(t, now, []string{"services", "--report", report})
	if code != 1 || !strings.Contains(stdout, "eslint-missing") || strings.Contains(stdout, "waived") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	decoded, _ := readESLintReport(t, report)
	if decoded.ESLintVersion != "" || len(decoded.Verdicts) != 1 || decoded.Verdicts[0].Result != "error" || decoded.Verdicts[0].Violations != 0 {
		t.Fatalf("report %+v", decoded)
	}
}

// The tests below run the pinned ESLint toolchain. They need IPSO_ESLINT=1 and eslint 10.13.0 on PATH,
// installed with `npm ci --ignore-scripts` in internal/compiler/eslint/testdata/tool.

func requireESLint(t *testing.T) {
	t.Helper()
	if os.Getenv("IPSO_ESLINT") == "" {
		t.Skip("IPSO_ESLINT is not set")
	}
	if _, err := exec.LookPath("eslint"); err != nil {
		t.Fatal("eslint is not on PATH")
	}
}

func TestCheckESLintRealCleanAndViolating(t *testing.T) {
	requireESLint(t)
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	both := eslintTSCheck + eslintJSCheck

	eslintRepo(t, now, both, false, "app-clean")
	stdout, stderr, code := eslintAt(t, now, []string{"services", "web"})
	if code != 0 || !strings.Contains(stdout, "app: checks[0] (block): pass") || !strings.Contains(stdout, "app: checks[1] (block): pass") {
		t.Fatalf("clean code %d\n%s\n%s", code, stdout, stderr)
	}

	// The violating subject carries an eslint-disable comment and an eslint-suppressions.json
	// that would hide both findings if ESLint applied them.
	root := eslintRepo(t, now, both, false, "app-violating")
	report := filepath.Join(root, "report.json")
	stdout, stderr, code = eslintAt(t, now, []string{"services", "web", "--report", report})
	if code != 1 || strings.Count(stdout, "(block): ") != 2 ||
		!strings.Contains(stdout, "app: checks[0] (block): @typescript-eslint/no-floating-promises services/float.ts:3:3: ") ||
		!strings.Contains(stdout, "app: checks[1] (block): eqeqeq web/eq.js:2:15: ") {
		t.Fatalf("violating code %d\n%s\n%s", code, stdout, stderr)
	}
	decoded, body := readESLintReport(t, report)
	for _, leaked := range []string{"no-floating-promises", "eqeqeq", "float.ts", "eq.js", "Promises must", "Expected"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("report carries %q: %s", leaked, body)
		}
	}
	if decoded.ReportVersion != 2 || decoded.ESLintVersion != "10.13.0" || len(decoded.BuildSHA256) != 64 || len(decoded.Paths) != 2 {
		t.Fatalf("report %+v", decoded)
	}
	if len(decoded.Verdicts) != 2 || decoded.Verdicts[0].Result != "fail" || decoded.Verdicts[0].Violations != 1 || decoded.Verdicts[1].Violations != 1 {
		t.Fatalf("verdicts %+v", decoded.Verdicts)
	}
	if info, err := os.Stat(report); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", info, err)
	}
}

func TestCheckESLintRealModeAndWaiver(t *testing.T) {
	requireESLint(t)
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)

	for _, mode := range []string{"warn", "advise"} {
		checks := strings.Replace(eslintTSCheck, "mode: block", "mode: "+mode, 1)
		eslintRepo(t, now, checks, false, "app-violating")
		stdout, stderr, code := eslintAt(t, now, []string{"services"})
		if code != 0 || !strings.Contains(stdout, "("+mode+"): @typescript-eslint/no-floating-promises services/float.ts:3:3") {
			t.Fatalf("%s code %d\n%s\n%s", mode, code, stdout, stderr)
		}
	}

	root := eslintRepo(t, now, eslintTSCheck, true, "app-violating")
	stdout, stderr, code := eslintAt(t, now, []string{"services"})
	if code != 0 || !strings.Contains(stdout, "app: checks[0] (block): waived") {
		t.Fatalf("waiver code %d\n%s\n%s", code, stdout, stderr)
	}

	// An error is never waived: a path that does not exist fails the check.
	stdout, stderr, code = eslintAt(t, now, []string{"nope"})
	if code != 1 || !strings.Contains(stdout, "eslint-path") || strings.Contains(stdout, "waived") {
		t.Fatalf("path code %d\n%s\n%s", code, stdout, stderr)
	}
	// A check that lints no file is an error too.
	writeRepoFile(t, root, "docs/notes.txt", "no source here\n")
	stdout, stderr, code = eslintAt(t, now, []string{"docs"})
	if code != 1 || !strings.Contains(stdout, "eslint-empty") || strings.Contains(stdout, "waived") {
		t.Fatalf("empty code %d\n%s\n%s", code, stdout, stderr)
	}
}
