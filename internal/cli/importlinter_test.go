package cli

import (
	"encoding/json"
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

const importlinterCheck = "  - engine: importlinter\n    ref: .importlinter\n    mode: block\n"

// importlinterTestdata is the import-linter compiler's testdata. It is anchored to this file because tests change directory.
func importlinterTestdata() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "compiler", "importlinter", "testdata")
}

func importlinterFixture(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(importlinterTestdata(), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// importlinterRepo writes one in-force decision that points at the shop rule file and compiles it.
func importlinterRepo(t *testing.T, now time.Time, checks string, waiver bool) string {
	t.Helper()
	root := t.TempDir()
	withDir(t, root)
	record := compileRecord(idA, "shop", "accepted", "blocking", "2026-01-01", "", checks)
	if waiver {
		record = strings.Replace(record, "\nwaivers: []\n", "\nwaivers:\n  - reason: cutover\n    approver: Ada Lovelace\n    valid_from: 2026-01-01\n    valid_to: 2026-03-01\n", 1)
	}
	writeRepoFile(t, root, "docs/decisions/shop.md", record)
	writeRepoFile(t, root, ".importlinter", importlinterFixture(t, "shop-violating/repo/.importlinter"))
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", stderr)
	}
	return root
}

// writeShop writes the Python of one fixture subject into the repository.
func writeShop(t *testing.T, root, subject string) {
	t.Helper()
	for _, pkg := range []string{"", "api", "billing", "domain", "infra", "shipping"} {
		rel := "shop/" + pkg + "/__init__.py"
		if pkg == "" {
			rel = "shop/__init__.py"
		}
		writeRepoFile(t, root, rel, importlinterFixture(t, subject+"/repo/"+rel+".fixture"))
	}
}

func importlinterAt(t *testing.T, now time.Time, args []string) (string, string, int) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := run(append([]string{"check", "importlinter"}, args...), &stdout, &stderr, deps{now: func() time.Time { return now }, registry: builtin.Registry()})
	return stdout.String(), stderr.String(), code
}

func readImportLinterReport(t *testing.T, path string) (compiler.ImportLinterReport, string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded compiler.ImportLinterReport
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded, string(body)
}

func TestCheckImportlinterUsage(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	for _, args := range [][]string{
		{},
		{"--env", "prod"},
		{"--report", "out.json"},
		{".", "--jars", "lib"},
		{"../x"},
		{"/abs"},
		{"src/*"},
		{"-x"},
		{".", "--env"},
		{".", "--env", "--report", "out.json"},
		{".", "--report"},
		{".", "--env", "prod", "--env", "dev"},
		{".", "--bogus"},
	} {
		stdout, stderr, code := importlinterAt(t, now, args)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "usage: ipso check importlinter") {
			t.Fatalf("args %q code %d stdout %q stderr %q", args, code, stdout, stderr)
		}
	}
}

func TestCheckUsageListsImportlinter(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := run([]string{"check", "bogus"}, &stdout, &stderr, deps{registry: builtin.Registry()}); code != 2 || !strings.Contains(stderr.String(), importlinterUsage) {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	stdout.Reset()
	if code := run([]string{"help"}, &stdout, &stderr, deps{registry: builtin.Registry()}); code != 0 || !strings.Contains(stdout.String(), "ipso check importlinter <source-dir>...") {
		t.Fatalf("code %d stdout %s", code, stdout.String())
	}
}

func TestCheckImportlinterNeedsABuild(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	withDir(t, t.TempDir())
	_, stderr, code := importlinterAt(t, now, []string{"."})
	if code != 1 || !strings.Contains(stderr, "build-missing") {
		t.Fatalf("code %d stderr %s", code, stderr)
	}
}

func TestCheckImportlinterSelectsNothing(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := importlinterRepo(t, now, importlinterCheck, false)
	record := compileRecord(idA, "shop", "accepted", "blocking", "2026-01-01", "", importlinterCheck)
	record = strings.Replace(record, "  - org: acme\n", "  - org: acme\n    env: [prod]\n", 1)
	writeRepoFile(t, root, "docs/decisions/shop.md", record)
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", stderr)
	}
	// Neither python nor the source directory is needed when nothing is selected.
	t.Setenv("PATH", t.TempDir())
	report := filepath.Join(root, "none.json")
	stdout, stderr, code := importlinterAt(t, now, []string{"missing", "--env", "dev", "--report", report})
	if code != 0 || !strings.Contains(stdout, "no checks selected") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	decoded, _ := readImportLinterReport(t, report)
	if decoded.ImportLinterVersion != "" || len(decoded.Verdicts) != 0 || len(decoded.Paths) != 1 || decoded.Paths[0] != "missing" || decoded.Env != "dev" {
		t.Fatalf("report %+v", decoded)
	}
}

func TestCheckImportlinterPythonFailureIsAnErrorEvenWithAWaiver(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := importlinterRepo(t, now, importlinterCheck, true)
	writeShop(t, root, "shop-violating")
	t.Setenv("PATH", t.TempDir())
	report := filepath.Join(root, "report.json")
	stdout, stderr, code := importlinterAt(t, now, []string{".", "--report", report})
	if code != 1 || !strings.Contains(stdout, "importlinter-missing") || strings.Contains(stdout, "waived") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	decoded, _ := readImportLinterReport(t, report)
	if decoded.ImportLinterVersion != "" || len(decoded.Verdicts) != 1 || decoded.Verdicts[0].Result != "error" || decoded.Verdicts[0].Violations != 0 {
		t.Fatalf("report %+v", decoded)
	}
}

func TestCheckImportlinterSourceDirectoryProblemsAreErrors(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := importlinterRepo(t, now, importlinterCheck, true)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("no symlinks: %v", err)
	}
	for _, dir := range []string{"nope", "escape"} {
		stdout, stderr, code := importlinterAt(t, now, []string{dir})
		if code != 1 || !strings.Contains(stdout, "importlinter-path") || strings.Contains(stdout, "waived") {
			t.Fatalf("%s: code %d\n%s\n%s", dir, code, stdout, stderr)
		}
	}
}

// The tests below run the pinned import-linter. They need IPSO_IMPORTLINTER=1 and a python on PATH
// that carries import-linter and grimp from the hash-locked requirements.

func requireImportLinter(t *testing.T) {
	t.Helper()
	if os.Getenv("IPSO_IMPORTLINTER") == "" {
		t.Skip("IPSO_IMPORTLINTER is not set")
	}
	if _, err := exec.LookPath("python"); err != nil {
		t.Fatal("python is not on PATH")
	}
}

func TestCheckImportlinterRealCleanAndViolating(t *testing.T) {
	requireImportLinter(t)
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := importlinterRepo(t, now, importlinterCheck, false)

	// The rule file is the violating shop's, and the clean shop keeps all three contracts.
	writeShop(t, root, "shop-clean")
	stdout, stderr, code := importlinterAt(t, now, []string{"."})
	if code != 0 || !strings.Contains(stdout, "shop: checks[0] (block): pass") {
		t.Fatalf("clean code %d\n%s\n%s", code, stdout, stderr)
	}

	writeShop(t, root, "shop-violating")
	report := filepath.Join(root, "report.json")
	stdout, stderr, code = importlinterAt(t, now, []string{".", "--report", report})
	if code != 1 || strings.Count(stdout, "(block): ") != 3 || !strings.Contains(stdout, "(block): layers shop.domain -> shop.api (l.1)") {
		t.Fatalf("violating code %d\n%s\n%s", code, stdout, stderr)
	}
	decoded, body := readImportLinterReport(t, report)
	for _, leaked := range []string{"Layers", "Independence", "Forbidden", "shop.domain", "shop.api", "shop.billing"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("report carries %q: %s", leaked, body)
		}
	}
	if decoded.ReportVersion != 2 || decoded.ImportLinterVersion != "2.15" || len(decoded.BuildSHA256) != 64 || len(decoded.Paths) != 1 || decoded.Paths[0] != "." {
		t.Fatalf("report %+v", decoded)
	}
	if len(decoded.Verdicts) != 1 || decoded.Verdicts[0].Result != "fail" || decoded.Verdicts[0].Violations != 3 {
		t.Fatalf("verdicts %+v", decoded.Verdicts)
	}
	if info, err := os.Stat(report); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", info, err)
	}
}

func TestCheckImportlinterRealModeAndWaiver(t *testing.T) {
	requireImportLinter(t)
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)

	root := importlinterRepo(t, now, "  - engine: importlinter\n    ref: .importlinter\n    mode: warn\n", false)
	writeShop(t, root, "shop-violating")
	stdout, stderr, code := importlinterAt(t, now, []string{"."})
	if code != 0 || !strings.Contains(stdout, "(warn): layers shop.domain -> shop.api (l.1)") {
		t.Fatalf("warn code %d\n%s\n%s", code, stdout, stderr)
	}

	root = importlinterRepo(t, now, importlinterCheck, true)
	writeShop(t, root, "shop-violating")
	stdout, stderr, code = importlinterAt(t, now, []string{"."})
	if code != 0 || !strings.Contains(stdout, "waived") {
		t.Fatalf("waiver code %d\n%s\n%s", code, stdout, stderr)
	}

	// An error is never waived: a source directory that does not hold the root package fails the check.
	if err := os.Mkdir(filepath.Join(root, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = importlinterAt(t, now, []string{"empty"})
	if code != 1 || !strings.Contains(stdout, "importlinter-empty") || strings.Contains(stdout, "waived") {
		t.Fatalf("empty code %d\n%s\n%s", code, stdout, stderr)
	}
}
