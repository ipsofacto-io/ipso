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

const archunitCheck = "  - engine: archunit\n    ref: archunit.json\n    mode: block\n"

// archunitTestdata is the ArchUnit compiler's testdata. It is anchored to this file because tests change directory.
func archunitTestdata() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "compiler", "archunit", "testdata")
}

func archunitFixture(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(archunitTestdata(), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// archunitRepo writes one in-force decision that points at the billing rule file and compiles it.
func archunitRepo(t *testing.T, now time.Time, checks string, waiver bool) string {
	t.Helper()
	root := t.TempDir()
	rules := archunitFixture(t, "billing-violating/repo/archunit.json")
	withDir(t, root)
	record := compileRecord(idA, "billing", "accepted", "blocking", "2026-01-01", "", checks)
	if waiver {
		record = strings.Replace(record, "\nwaivers: []\n", "\nwaivers:\n  - reason: cutover\n    approver: Ada Lovelace\n    valid_from: 2026-01-01\n    valid_to: 2026-03-01\n", 1)
	}
	writeRepoFile(t, root, "docs/decisions/billing.md", record)
	writeRepoFile(t, root, "archunit.json", rules)
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", stderr)
	}
	return root
}

func archunitAt(t *testing.T, now time.Time, args []string) (string, string, int) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := run(append([]string{"check", "archunit"}, args...), &stdout, &stderr, deps{now: func() time.Time { return now }, registry: builtin.Registry()})
	return stdout.String(), stderr.String(), code
}

func TestCheckArchunitUsage(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	for _, args := range [][]string{
		{},
		{"--jars", "lib"},
		{"target/classes"},
		{"target/classes", "--jars"},
		{"target/classes", "--jars", "--env", "prod"},
		{"target/classes", "--jars", "lib", "--jars", "other"},
		{"../x", "--jars", "lib"},
		{"/abs", "--jars", "lib"},
		{"target/*", "--jars", "lib"},
		{"-x", "--jars", "lib"},
		{"target/classes", "--jars", "lib", "--env"},
		{"target/classes", "--jars", "lib", "--report"},
		{"target/classes", "--jars", "lib", "--bogus"},
	} {
		stdout, stderr, code := archunitAt(t, now, args)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "usage: ipso check archunit") {
			t.Fatalf("args %q code %d stdout %q stderr %q", args, code, stdout, stderr)
		}
	}
}

// --jars belongs to ipso check archunit alone.
func TestCheckPathCommandsRefuseJars(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	for _, engine := range []string{"semgrep", "depcruise", "importlinter"} {
		var stdout, stderr strings.Builder
		code := run([]string{"check", engine, "src", "--jars", "lib"}, &stdout, &stderr, deps{now: func() time.Time { return now }, registry: builtin.Registry()})
		if code != 2 {
			t.Fatalf("%s accepted --jars: code %d", engine, code)
		}
	}
}

func TestCheckArchunitNeedsABuild(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	withDir(t, t.TempDir())
	_, stderr, code := archunitAt(t, now, []string{"target/classes", "--jars", "lib"})
	if code != 1 || !strings.Contains(stderr, "build-missing") {
		t.Fatalf("code %d stderr %s", code, stderr)
	}
}

func TestCheckArchunitSelectsNothing(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := archunitRepo(t, now, archunitCheck, false)
	record := compileRecord(idA, "billing", "accepted", "blocking", "2026-01-01", "", archunitCheck)
	record = strings.Replace(record, "  - org: acme\n", "  - org: acme\n    env: [prod]\n", 1)
	writeRepoFile(t, root, "docs/decisions/billing.md", record)
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", stderr)
	}
	// Neither the jars, nor a JDK, nor the class directory is needed when nothing is selected.
	t.Setenv("PATH", t.TempDir())
	report := filepath.Join(root, "none.json")
	stdout, stderr, code := archunitAt(t, now, []string{"target/classes", "--jars", "missing", "--env", "dev", "--report", report})
	if code != 0 || !strings.Contains(stdout, "no checks selected") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	body, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded compiler.ArchUnitReport
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ArchUnitVersion != "" || len(decoded.Verdicts) != 0 || len(decoded.Paths) != 1 || decoded.Paths[0] != "target/classes" || decoded.Env != "dev" {
		t.Fatalf("report %+v", decoded)
	}
}

func TestCheckArchunitJarFailureIsAnErrorEvenWithAWaiver(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := archunitRepo(t, now, archunitCheck, true)
	jars := t.TempDir()
	report := filepath.Join(root, "report.json")
	stdout, stderr, code := archunitAt(t, now, []string{"target/classes", "--jars", jars, "--report", report})
	if code != 1 || !strings.Contains(stdout, "archunit-jar") || strings.Contains(stdout, "waived") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	body, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded compiler.ArchUnitReport
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ArchUnitVersion != "" || len(decoded.Verdicts) != 1 || decoded.Verdicts[0].Result != "error" || decoded.Verdicts[0].Violations != 0 {
		t.Fatalf("report %+v", decoded)
	}
}

// The tests below run the pinned jars. They need IPSO_ARCHUNIT=1, a JDK on PATH, and the jars from install.sh.

func realArchUnitJars(t *testing.T) string {
	t.Helper()
	if os.Getenv("IPSO_ARCHUNIT") == "" {
		t.Skip("IPSO_ARCHUNIT is not set")
	}
	if _, err := exec.LookPath("javac"); err != nil {
		t.Fatal("javac is not on PATH")
	}
	return filepath.Join(archunitTestdata(), "tool", "lib")
}

// compileBilling writes the Java of one fixture subject into the working directory and compiles it to target/classes.
func compileBilling(t *testing.T, root, subject string) {
	t.Helper()
	var sources []string
	for _, dir := range []string{"domain", "persistence", "web"} {
		entries, err := os.ReadDir(filepath.Join(archunitTestdata(), subject, "repo", "src", "main", "java", "com", "acme", "billing", dir))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			name := strings.TrimSuffix(entry.Name(), ".fixture")
			rel := "src/com/acme/billing/" + dir + "/" + name
			writeRepoFile(t, root, rel, archunitFixture(t, subject+"/repo/src/main/java/com/acme/billing/"+dir+"/"+entry.Name()))
			sources = append(sources, filepath.Join(root, filepath.FromSlash(rel)))
		}
	}
	classes := filepath.Join(root, "target", "classes")
	if err := os.MkdirAll(classes, 0o755); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"--release", "17", "-proc:none", "-d", classes}, sources...)
	if out, err := exec.Command("javac", args...).CombinedOutput(); err != nil {
		t.Fatalf("javac: %v\n%s", err, out)
	}
}

func TestCheckArchunitRealCleanAndViolating(t *testing.T) {
	jars := realArchUnitJars(t)
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := archunitRepo(t, now, archunitCheck, false)

	compileBilling(t, root, "billing-clean")
	stdout, stderr, code := archunitAt(t, now, []string{"target/classes", "--jars", jars})
	if code != 0 || !strings.Contains(stdout, "billing: checks[0] (block): pass") {
		t.Fatalf("clean code %d\n%s\n%s", code, stdout, stderr)
	}

	if err := os.RemoveAll(filepath.Join(root, "target")); err != nil {
		t.Fatal(err)
	}
	compileBilling(t, root, "billing-violating")
	report := filepath.Join(root, "report.json")
	stdout, stderr, code = archunitAt(t, now, []string{"target/classes", "--jars", jars, "--report", report})
	if code != 1 || !strings.Contains(stdout, "domain-not-to-adapters Method <com.acme.billing.domain.Order.leak()>") || strings.Count(stdout, "(block): ") != 5 {
		t.Fatalf("violating code %d\n%s\n%s", code, stdout, stderr)
	}
	body, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"domain-not-to-adapters", "layers", "Order", "leak", "billing/", "com.acme"} {
		if strings.Contains(string(body), leaked) {
			t.Fatalf("report carries %q: %s", leaked, body)
		}
	}
	var decoded compiler.ArchUnitReport
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ReportVersion != 2 || decoded.ArchUnitVersion != "1.5.1" || len(decoded.BuildSHA256) != 64 || len(decoded.Paths) != 1 || decoded.Paths[0] != "target/classes" {
		t.Fatalf("report %+v", decoded)
	}
	if len(decoded.Verdicts) != 1 || decoded.Verdicts[0].Result != "fail" || decoded.Verdicts[0].Violations != 5 {
		t.Fatalf("verdicts %+v", decoded.Verdicts)
	}
	if info, err := os.Stat(report); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", info, err)
	}
}

func TestCheckArchunitRealModeAndWaiver(t *testing.T) {
	jars := realArchUnitJars(t)
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)

	root := archunitRepo(t, now, "  - engine: archunit\n    ref: archunit.json\n    mode: warn\n", false)
	compileBilling(t, root, "billing-violating")
	stdout, stderr, code := archunitAt(t, now, []string{"target/classes", "--jars", jars})
	if code != 0 || !strings.Contains(stdout, "(warn): domain-not-to-adapters") {
		t.Fatalf("warn code %d\n%s\n%s", code, stdout, stderr)
	}

	root = archunitRepo(t, now, archunitCheck, true)
	compileBilling(t, root, "billing-violating")
	stdout, stderr, code = archunitAt(t, now, []string{"target/classes", "--jars", jars})
	if code != 0 || !strings.Contains(stdout, "waived") {
		t.Fatalf("waiver code %d\n%s\n%s", code, stdout, stderr)
	}

	// An error is never waived: a class directory that is not there fails the check.
	stdout, stderr, code = archunitAt(t, now, []string{"nope", "--jars", jars})
	if code != 1 || !strings.Contains(stdout, "archunit-path") || strings.Contains(stdout, "waived") {
		t.Fatalf("path code %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestCheckArchunitRealSymlinkLeavingTheRepository(t *testing.T) {
	jars := realArchUnitJars(t)
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := archunitRepo(t, now, archunitCheck, false)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("no symlinks: %v", err)
	}
	stdout, stderr, code := archunitAt(t, now, []string{"escape", "--jars", jars})
	if code != 1 || !strings.Contains(stdout, "archunit-path") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
}
