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

const kyvernoCheck = "  - engine: kyverno\n    ref: policies/run-as-non-root.yaml\n    mode: block\n"

// kyvernoTestdata is the Kyverno compiler's testdata. It is anchored to this file because tests change directory.
func kyvernoTestdata() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "compiler", "kyverno", "testdata")
}

func kyvernoFixture(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(kyvernoTestdata(), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// kyvernoRepo writes one in-force decision that points at the run-as-non-root policy and compiles it.
func kyvernoRepo(t *testing.T, now time.Time, checks string, waiver bool) string {
	t.Helper()
	root := t.TempDir()
	withDir(t, root)
	record := compileRecord(idA, "pods", "accepted", "blocking", "2026-01-01", "", checks)
	if waiver {
		record = strings.Replace(record, "\nwaivers: []\n", "\nwaivers:\n  - reason: cutover\n    approver: Ada Lovelace\n    valid_from: 2026-01-01\n    valid_to: 2026-03-01\n", 1)
	}
	writeRepoFile(t, root, "docs/decisions/pods.md", record)
	writeRepoFile(t, root, "policies/run-as-non-root.yaml", kyvernoFixture(t, "cluster-violating/repo/policies/run-as-non-root.yaml"))
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", stderr)
	}
	return root
}

// writePod writes the pod of one fixture subject into the repository.
func writePod(t *testing.T, root, subject string) {
	t.Helper()
	writeRepoFile(t, root, "k8s/api.yaml", kyvernoFixture(t, subject+"/repo/pods/api.yaml.fixture"))
}

func kyvernoAt(t *testing.T, now time.Time, args []string) (string, string, int) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := run(append([]string{"check", "kyverno"}, args...), &stdout, &stderr, deps{now: func() time.Time { return now }, registry: builtin.Registry()})
	return stdout.String(), stderr.String(), code
}

func readKyvernoReport(t *testing.T, path string) (compiler.KyvernoReport, string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded compiler.KyvernoReport
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded, string(body)
}

func TestCheckKyvernoUsage(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	for _, args := range [][]string{
		{},
		{"--env", "prod"},
		{"--report", "out.json"},
		{"k8s", "--jars", "lib"},
		{"../x"},
		{"/abs"},
		{"k8s/*"},
		{"-x"},
		{"k8s", "--env"},
		{"k8s", "--env", "--report", "out.json"},
		{"k8s", "--report"},
		{"k8s", "--env", "prod", "--env", "dev"},
		{"k8s", "--bogus"},
	} {
		stdout, stderr, code := kyvernoAt(t, now, args)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "usage: ipso check kyverno") {
			t.Fatalf("args %q code %d stdout %q stderr %q", args, code, stdout, stderr)
		}
	}
}

func TestCheckUsageListsKyverno(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := run([]string{"check", "bogus"}, &stdout, &stderr, deps{registry: builtin.Registry()}); code != 2 || !strings.Contains(stderr.String(), kyvernoUsage) {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	stdout.Reset()
	if code := run([]string{"help"}, &stdout, &stderr, deps{registry: builtin.Registry()}); code != 0 || !strings.Contains(stdout.String(), "ipso check kyverno <path>...") {
		t.Fatalf("code %d stdout %s", code, stdout.String())
	}
}

func TestCheckKyvernoNeedsABuild(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	withDir(t, t.TempDir())
	_, stderr, code := kyvernoAt(t, now, []string{"k8s"})
	if code != 1 || !strings.Contains(stderr, "build-missing") {
		t.Fatalf("code %d stderr %s", code, stderr)
	}
}

func TestCheckKyvernoSelectsNothing(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := kyvernoRepo(t, now, kyvernoCheck, false)
	record := compileRecord(idA, "pods", "accepted", "blocking", "2026-01-01", "", kyvernoCheck)
	record = strings.Replace(record, "  - org: acme\n", "  - org: acme\n    env: [prod]\n", 1)
	writeRepoFile(t, root, "docs/decisions/pods.md", record)
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", stderr)
	}
	// Neither kyverno nor the manifests are needed when nothing is selected.
	t.Setenv("PATH", t.TempDir())
	report := filepath.Join(root, "none.json")
	stdout, stderr, code := kyvernoAt(t, now, []string{"missing", "--env", "dev", "--report", report})
	if code != 0 || !strings.Contains(stdout, "no checks selected") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	decoded, _ := readKyvernoReport(t, report)
	if decoded.KyvernoVersion != "" || len(decoded.Verdicts) != 0 || len(decoded.Paths) != 1 || decoded.Paths[0] != "missing" || decoded.Env != "dev" {
		t.Fatalf("report %+v", decoded)
	}
}

func TestCheckKyvernoMissingBinaryIsAnErrorEvenWithAWaiver(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := kyvernoRepo(t, now, kyvernoCheck, true)
	writePod(t, root, "cluster-violating")
	t.Setenv("PATH", t.TempDir())
	report := filepath.Join(root, "report.json")
	stdout, stderr, code := kyvernoAt(t, now, []string{"k8s", "--report", report})
	if code != 1 || !strings.Contains(stdout, "kyverno-missing") || strings.Contains(stdout, "waived") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	decoded, _ := readKyvernoReport(t, report)
	if decoded.KyvernoVersion != "" || len(decoded.Verdicts) != 1 || decoded.Verdicts[0].Result != "error" || decoded.Verdicts[0].Violations != 0 {
		t.Fatalf("report %+v", decoded)
	}
}

// The tests below run the pinned Kyverno CLI. They need IPSO_KYVERNO=1 and kyverno 1.19.2 on PATH,
// installed with internal/compiler/kyverno/testdata/tool/install.sh.

func requireKyverno(t *testing.T) {
	t.Helper()
	if os.Getenv("IPSO_KYVERNO") == "" {
		t.Skip("IPSO_KYVERNO is not set")
	}
	if _, err := exec.LookPath("kyverno"); err != nil {
		t.Fatal("kyverno is not on PATH")
	}
}

func TestCheckKyvernoRealCleanAndViolating(t *testing.T) {
	requireKyverno(t)
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := kyvernoRepo(t, now, kyvernoCheck, false)

	writePod(t, root, "cluster-clean")
	stdout, stderr, code := kyvernoAt(t, now, []string{"k8s"})
	if code != 0 || !strings.Contains(stdout, "pods: checks[0] (block): pass") {
		t.Fatalf("clean code %d\n%s\n%s", code, stdout, stderr)
	}

	writePod(t, root, "cluster-violating")
	report := filepath.Join(root, "report.json")
	stdout, stderr, code = kyvernoAt(t, now, []string{"k8s", "--report", report})
	if code != 1 || strings.Count(stdout, "(block): ") != 1 || !strings.Contains(stdout, "pods: checks[0] (block): default/Pod/api: runAsNonRoot must be true") {
		t.Fatalf("violating code %d\n%s\n%s", code, stdout, stderr)
	}
	decoded, body := readKyvernoReport(t, report)
	for _, leaked := range []string{"run-as-non-root", "runAsNonRoot", "Pod", "api", "default"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("report carries %q: %s", leaked, body)
		}
	}
	if decoded.ReportVersion != 2 || decoded.KyvernoVersion != "1.19.2" || len(decoded.BuildSHA256) != 64 || len(decoded.Paths) != 1 || decoded.Paths[0] != "k8s" {
		t.Fatalf("report %+v", decoded)
	}
	if len(decoded.Verdicts) != 1 || decoded.Verdicts[0].Result != "fail" || decoded.Verdicts[0].Violations != 1 {
		t.Fatalf("verdicts %+v", decoded.Verdicts)
	}
	if info, err := os.Stat(report); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", info, err)
	}
}

func TestCheckKyvernoRealModeAndWaiver(t *testing.T) {
	requireKyverno(t)
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)

	for _, mode := range []string{"warn", "advise"} {
		root := kyvernoRepo(t, now, "  - engine: kyverno\n    ref: policies/run-as-non-root.yaml\n    mode: "+mode+"\n", false)
		writePod(t, root, "cluster-violating")
		stdout, stderr, code := kyvernoAt(t, now, []string{"k8s"})
		if code != 0 || !strings.Contains(stdout, "("+mode+"): default/Pod/api: runAsNonRoot must be true") {
			t.Fatalf("%s code %d\n%s\n%s", mode, code, stdout, stderr)
		}
	}

	root := kyvernoRepo(t, now, kyvernoCheck, true)
	writePod(t, root, "cluster-violating")
	stdout, stderr, code := kyvernoAt(t, now, []string{"k8s"})
	if code != 0 || !strings.Contains(stdout, "waived") {
		t.Fatalf("waiver code %d\n%s\n%s", code, stdout, stderr)
	}

	// An error is never waived: a directory with no manifest fails the check.
	if err := os.Mkdir(filepath.Join(root, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = kyvernoAt(t, now, []string{"empty"})
	if code != 1 || !strings.Contains(stdout, "kyverno-empty") || strings.Contains(stdout, "waived") {
		t.Fatalf("empty code %d\n%s\n%s", code, stdout, stderr)
	}
}
