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

const gatekeeperCheck = "  - engine: opa\n    target: gatekeeper\n    ref: policies/gatekeeper.yaml\n    mode: block\n"

// gatekeeperTestdata is the Gatekeeper evaluation's testdata. It is anchored to this file because tests change directory.
func gatekeeperTestdata() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "compiler", "gatekeeper", "testdata")
}

// opaTestdata is the OPA compiler's testdata, which holds the Gatekeeper conformance subjects.
func opaTestdata() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "compiler", "opa", "testdata")
}

func gatekeeperFixture(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(opaTestdata(), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// gatekeeperRepo writes one in-force decision that points at the owner label policy and compiles it.
func gatekeeperRepo(t *testing.T, now time.Time, checks string, waiver bool) string {
	t.Helper()
	root := t.TempDir()
	withDir(t, root)
	record := compileRecord(idA, "owner", "accepted", "blocking", "2026-01-01", "", checks)
	if waiver {
		record = strings.Replace(record, "\nwaivers: []\n", "\nwaivers:\n  - reason: cutover\n    approver: Ada Lovelace\n    valid_from: 2026-01-01\n    valid_to: 2026-03-01\n", 1)
	}
	writeRepoFile(t, root, "docs/decisions/owner.md", record)
	writeRepoFile(t, root, "policies/gatekeeper.yaml", gatekeeperFixture(t, "gatekeeper-violating/repo/gatekeeper.yaml"))
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", stderr)
	}
	return root
}

// writeDeployment writes the deployment of one fixture subject into the repository.
func writeDeployment(t *testing.T, root, subject string) {
	t.Helper()
	writeRepoFile(t, root, "apps/api.yaml", gatekeeperFixture(t, subject+"/repo/apps/api.yaml.fixture"))
}

func gatekeeperAt(t *testing.T, now time.Time, args []string) (string, string, int) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := run(append([]string{"check", "gatekeeper"}, args...), &stdout, &stderr, deps{now: func() time.Time { return now }, registry: builtin.Registry()})
	return stdout.String(), stderr.String(), code
}

func readGatekeeperReport(t *testing.T, path string) (compiler.GatekeeperReport, string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded compiler.GatekeeperReport
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded, string(body)
}

func TestCheckGatekeeperUsage(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	for _, args := range [][]string{
		{},
		{"--env", "prod"},
		{"--report", "out.json"},
		{"apps", "--jars", "lib"},
		{"../x"},
		{"/abs"},
		{"apps/*"},
		{"-x"},
		{"apps", "--env"},
		{"apps", "--env", "--report", "out.json"},
		{"apps", "--report"},
		{"apps", "--env", "prod", "--env", "dev"},
		{"apps", "--bogus"},
	} {
		stdout, stderr, code := gatekeeperAt(t, now, args)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "usage: ipso check gatekeeper") {
			t.Fatalf("args %q code %d stdout %q stderr %q", args, code, stdout, stderr)
		}
	}
}

func TestCheckUsageListsGatekeeper(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := run([]string{"check", "bogus"}, &stdout, &stderr, deps{registry: builtin.Registry()}); code != 2 || !strings.Contains(stderr.String(), gatekeeperUsage) {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	stdout.Reset()
	if code := run([]string{"help"}, &stdout, &stderr, deps{registry: builtin.Registry()}); code != 0 || !strings.Contains(stdout.String(), "ipso check gatekeeper <path>...") {
		t.Fatalf("code %d stdout %s", code, stdout.String())
	}
}

func TestCheckGatekeeperNeedsABuild(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	withDir(t, t.TempDir())
	_, stderr, code := gatekeeperAt(t, now, []string{"apps"})
	if code != 1 || !strings.Contains(stderr, "build-missing") {
		t.Fatalf("code %d stderr %s", code, stderr)
	}
}

func TestCheckGatekeeperSelectsNothing(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := gatekeeperRepo(t, now, gatekeeperCheck, false)
	record := compileRecord(idA, "owner", "accepted", "blocking", "2026-01-01", "", gatekeeperCheck)
	record = strings.Replace(record, "  - org: acme\n", "  - org: acme\n    env: [prod]\n", 1)
	writeRepoFile(t, root, "docs/decisions/owner.md", record)
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", stderr)
	}
	// Neither gator nor the manifests are needed when nothing is selected.
	t.Setenv("PATH", t.TempDir())
	report := filepath.Join(root, "none.json")
	stdout, stderr, code := gatekeeperAt(t, now, []string{"missing", "--env", "dev", "--report", report})
	if code != 0 || !strings.Contains(stdout, "no checks selected") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	decoded, _ := readGatekeeperReport(t, report)
	if decoded.GatorVersion != "" || len(decoded.Verdicts) != 0 || len(decoded.Paths) != 1 || decoded.Paths[0] != "missing" || decoded.Env != "dev" {
		t.Fatalf("report %+v", decoded)
	}
}

// A Terraform plan template is an OPA check too. This command takes only the Gatekeeper ones.
func TestCheckGatekeeperIgnoresOtherChecks(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	checks := gatekeeperCheck + "  - engine: opa\n    target: terraform-plan\n    ref: ipso:aws/ebs-encrypted\n  - engine: kyverno\n    ref: policies/run-as-non-root.yaml\n"
	root := t.TempDir()
	withDir(t, root)
	writeRepoFile(t, root, "docs/decisions/owner.md", compileRecord(idA, "owner", "accepted", "blocking", "2026-01-01", "", checks))
	writeRepoFile(t, root, "policies/gatekeeper.yaml", gatekeeperFixture(t, "gatekeeper-violating/repo/gatekeeper.yaml"))
	writeRepoFile(t, root, "policies/run-as-non-root.yaml", kyvernoFixture(t, "cluster-violating/repo/policies/run-as-non-root.yaml"))
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", stderr)
	}
	t.Setenv("PATH", t.TempDir())
	report := filepath.Join(root, "report.json")
	stdout, _, code := gatekeeperAt(t, now, []string{"apps", "--report", report})
	if code != 1 || strings.Count(stdout, "gatekeeper-missing") != 1 || strings.Contains(stdout, "checks[1]") || strings.Contains(stdout, "checks[2]") {
		t.Fatalf("code %d\n%s", code, stdout)
	}
	decoded, _ := readGatekeeperReport(t, report)
	if len(decoded.Verdicts) != 1 || decoded.Verdicts[0].CheckIndex != 0 {
		t.Fatalf("verdicts %+v", decoded.Verdicts)
	}
}

func TestCheckGatekeeperMissingBinaryIsAnErrorEvenWithAWaiver(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := gatekeeperRepo(t, now, gatekeeperCheck, true)
	writeDeployment(t, root, "gatekeeper-violating")
	t.Setenv("PATH", t.TempDir())
	report := filepath.Join(root, "report.json")
	stdout, stderr, code := gatekeeperAt(t, now, []string{"apps", "--report", report})
	if code != 1 || !strings.Contains(stdout, "gatekeeper-missing") || strings.Contains(stdout, "waived") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	decoded, _ := readGatekeeperReport(t, report)
	if decoded.GatorVersion != "" || len(decoded.Verdicts) != 1 || decoded.Verdicts[0].Result != "error" || decoded.Verdicts[0].Violations != 0 {
		t.Fatalf("report %+v", decoded)
	}
}

// The tests below run the pinned gator CLI. They need IPSO_GATEKEEPER=1 and gator 3.23.1 on PATH,
// installed with internal/compiler/opa/testdata/tool/install.sh.

func requireGator(t *testing.T) {
	t.Helper()
	if os.Getenv("IPSO_GATEKEEPER") == "" {
		t.Skip("IPSO_GATEKEEPER is not set")
	}
	if _, err := exec.LookPath("gator"); err != nil {
		t.Fatal("gator is not on PATH")
	}
}

func TestCheckGatekeeperRealCleanAndViolating(t *testing.T) {
	requireGator(t)
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := gatekeeperRepo(t, now, gatekeeperCheck, false)

	writeDeployment(t, root, "gatekeeper-clean")
	stdout, stderr, code := gatekeeperAt(t, now, []string{"apps"})
	if code != 0 || !strings.Contains(stdout, "owner: checks[0] (block): pass") {
		t.Fatalf("clean code %d\n%s\n%s", code, stdout, stderr)
	}

	writeDeployment(t, root, "gatekeeper-violating")
	report := filepath.Join(root, "report.json")
	stdout, stderr, code = gatekeeperAt(t, now, []string{"apps", "--report", report})
	if code != 1 || strings.Count(stdout, "(block): ") != 1 || !strings.Contains(stdout, "owner: checks[0] (block): Deployment/api: missing owner label") {
		t.Fatalf("violating code %d\n%s\n%s", code, stdout, stderr)
	}
	decoded, body := readGatekeeperReport(t, report)
	for _, leaked := range []string{"RequireOwner", "requireowner", "missing owner", "Deployment", "api"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("report carries %q: %s", leaked, body)
		}
	}
	if decoded.ReportVersion != 2 || decoded.GatorVersion != "3.23.1" || len(decoded.BuildSHA256) != 64 || len(decoded.Paths) != 1 || decoded.Paths[0] != "apps" {
		t.Fatalf("report %+v", decoded)
	}
	if len(decoded.Verdicts) != 1 || decoded.Verdicts[0].Result != "fail" || decoded.Verdicts[0].Violations != 1 {
		t.Fatalf("verdicts %+v", decoded.Verdicts)
	}
	if info, err := os.Stat(report); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", info, err)
	}
}

func TestCheckGatekeeperRealModeAndWaiver(t *testing.T) {
	requireGator(t)
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)

	for _, mode := range []string{"warn", "advise"} {
		root := gatekeeperRepo(t, now, "  - engine: opa\n    target: gatekeeper\n    ref: policies/gatekeeper.yaml\n    mode: "+mode+"\n", false)
		writeDeployment(t, root, "gatekeeper-violating")
		stdout, stderr, code := gatekeeperAt(t, now, []string{"apps"})
		if code != 0 || !strings.Contains(stdout, "("+mode+"): Deployment/api: missing owner label") {
			t.Fatalf("%s code %d\n%s\n%s", mode, code, stdout, stderr)
		}
	}

	root := gatekeeperRepo(t, now, gatekeeperCheck, true)
	writeDeployment(t, root, "gatekeeper-violating")
	stdout, stderr, code := gatekeeperAt(t, now, []string{"apps"})
	if code != 0 || !strings.Contains(stdout, "waived") {
		t.Fatalf("waiver code %d\n%s\n%s", code, stdout, stderr)
	}

	// An error is never waived: a directory with no manifest fails the check.
	if err := os.Mkdir(filepath.Join(root, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = gatekeeperAt(t, now, []string{"empty"})
	if code != 1 || !strings.Contains(stdout, "gatekeeper-empty") || strings.Contains(stdout, "waived") {
		t.Fatalf("empty code %d\n%s\n%s", code, stdout, stderr)
	}
}

// The policy comes from the verified build. A policy file in the named paths, even one that would
// pass everything, is refused and never added to the run.
func TestCheckGatekeeperRealRefusesAPolicyInTheNamedPaths(t *testing.T) {
	requireGator(t)
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := gatekeeperRepo(t, now, gatekeeperCheck, true)
	writeDeployment(t, root, "gatekeeper-violating")
	writeRepoFile(t, root, "apps/constraint.yaml", "apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: RequireOwner\nmetadata:\n  name: owner\nspec:\n  enforcementAction: dryrun\n  match:\n    kinds:\n      - apiGroups: [apps]\n        kinds: [Deployment]\n")
	stdout, stderr, code := gatekeeperAt(t, now, []string{"apps"})
	if code != 1 || !strings.Contains(stdout, "gatekeeper-resource") || strings.Contains(stdout, "waived") {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
}
