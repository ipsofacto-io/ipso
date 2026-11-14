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

const cruiseRule = `{
  "forbidden": [
    {
      "name": "no-circular",
      "severity": "error",
      "from": {"path": "^src"},
      "to": {"circular": true}
    }
  ]
}
`

func TestCheckDepcruise(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	cruiseRepo(t, now, "  - engine: depcruise\n    target: typescript\n    ref: .dependency-cruiser.json\n    mode: block\n", false)
	withDepcruise(t, "18.7.0", cruiseReport("[]", "18.7.0"))
	stdout, stderr, code := depcruiseAt(t, now, []string{"."})
	if code != 0 || !strings.Contains(stdout, "monorepo: checks[0] (block): pass") {
		t.Fatalf("dot code %d\n%s\n%s", code, stdout, stderr)
	}

	withDepcruise(t, "18.7.0", cruiseReport(cruiseHit, "18.7.0"))
	stdout, stderr, code = depcruiseAt(t, now, []string{"packages"})
	if code != 1 || !strings.Contains(stdout, "secret-rule secret-module.ts -> other.ts") {
		t.Fatalf("fail code %d\n%s\n%s", code, stdout, stderr)
	}

	cruiseRepo(t, now, "  - engine: depcruise\n    target: typescript\n    ref: .dependency-cruiser.json\n    mode: warn\n", false)
	withDepcruise(t, "18.7.0", cruiseReport(cruiseHit, "18.7.0"))
	stdout, _, code = depcruiseAt(t, now, []string{"packages"})
	if code != 0 || !strings.Contains(stdout, "(warn): secret-rule") {
		t.Fatalf("warn code %d\n%s", code, stdout)
	}
}

func TestCheckDepcruiseSharesCruise(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	checks := "  - engine: depcruise\n    target: typescript\n    ref: .dependency-cruiser.json\n    mode: block\n  - engine: depcruise\n    target: typescript\n    ref: .dependency-cruiser.json\n    mode: block\n"
	cruiseRepo(t, now, checks, false)
	withDepcruise(t, "18.7.0", cruiseReport("[]", "18.7.0"))
	count := filepath.Join(t.TempDir(), "count")
	t.Setenv("FAKE_DEPCRUISE_COUNT", count)
	stdout, stderr, code := depcruiseAt(t, now, []string{"packages"})
	if code != 0 || strings.Count(stdout, "pass") != 2 {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	if got := strings.Count(readCount(t, count), "x"); got != 1 {
		t.Fatalf("cruises %d", got)
	}
}

func readCount(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestCheckDepcruiseWaiver(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	cruiseRepo(t, now, "  - engine: depcruise\n    target: typescript\n    ref: .dependency-cruiser.json\n    mode: block\n", true)
	withDepcruise(t, "18.7.0", cruiseReport(cruiseHit, "18.7.0"))
	stdout, stderr, code := depcruiseAt(t, now, []string{"packages"})
	if code != 0 || !strings.Contains(stdout, "waived") {
		t.Fatalf("waiver code %d\n%s\n%s", code, stdout, stderr)
	}

	t.Setenv("PATH", t.TempDir())
	stdout, stderr, code = depcruiseAt(t, now, []string{"packages"})
	if code != 1 || !strings.Contains(stdout, "depcruise-missing") || strings.Contains(stdout, "waived") {
		t.Fatalf("missing waiver code %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestCheckDepcruiseReport(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := cruiseRepo(t, now, "  - engine: depcruise\n    target: typescript\n    ref: .dependency-cruiser.json\n    mode: block\n", false)
	record := compileRecord(idA, "monorepo", "accepted", "blocking", "2026-01-01", "", "  - engine: depcruise\n    target: typescript\n    ref: .dependency-cruiser.json\n    mode: block\n")
	record = strings.Replace(record, "  - org: acme\n", "  - org: acme\n    env: [prod]\n", 1)
	writeRepoFile(t, root, "docs/decisions/boundary.md", record)
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile env: %s", stderr)
	}
	withDepcruise(t, "18.7.0", cruiseReport(cruiseHit, "18.7.0"))

	none := filepath.Join(root, "none.json")
	stdout, stderr, code := depcruiseAt(t, now, []string{"packages", "--env", "dev", "--report", none})
	if code != 0 || !strings.Contains(stdout, "no checks selected") {
		t.Fatalf("env code %d\n%s\n%s", code, stdout, stderr)
	}
	noneBody, err := os.ReadFile(none)
	if err != nil {
		t.Fatal(err)
	}
	var empty compiler.DepcruiseReport
	if err := json.Unmarshal(noneBody, &empty); err != nil {
		t.Fatal(err)
	}
	if empty.DepcruiseVersion != "" || len(empty.Verdicts) != 0 || len(empty.Paths) != 1 || empty.Paths[0] != "packages" {
		t.Fatalf("empty report %+v", empty)
	}

	report := filepath.Join(root, "report.json")
	stdout, stderr, code = depcruiseAt(t, now, []string{"packages", "--env", "prod", "--report", report})
	if code != 1 || !strings.Contains(stdout, "secret-module.ts") {
		t.Fatalf("report code %d\n%s\n%s", code, stdout, stderr)
	}
	body, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if strings.Contains(text, "secret-module.ts") || strings.Contains(text, "secret-rule") || strings.Contains(text, "other.ts") {
		t.Fatalf("report carries the finding: %s", text)
	}
	var decoded compiler.DepcruiseReport
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ReportVersion != 2 || decoded.Env != "prod" || len(decoded.Paths) != 1 || decoded.Paths[0] != "packages" || decoded.DepcruiseVersion != "18.7.0" || len(decoded.BuildSHA256) != 64 {
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

func TestCheckDepcruiseVersion(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	cruiseRepo(t, now, "  - engine: depcruise\n    target: typescript\n    ref: .dependency-cruiser.json\n    mode: block\n", false)
	withDepcruise(t, "19.0.0", cruiseReport(cruiseHit, "19.0.0"))
	stdout, stderr, code := depcruiseAt(t, now, []string{"packages"})
	if code != 1 || !strings.Contains(stdout, "depcruise-version") {
		t.Fatalf("version code %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestCheckDepcruiseUsage(t *testing.T) {
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	for _, args := range [][]string{{}, {"../x"}, {"/abs"}, {"src/*"}, {"src/../x"}, {"--config"}, {"packages", "--env"}, {"packages", "--bogus"}} {
		_, stderr, code := depcruiseAt(t, now, args)
		if code != 2 {
			t.Fatalf("args %q code %d stderr %s", args, code, stderr)
		}
	}
}

func cruiseRepo(t *testing.T, now time.Time, checks string, waiver bool) string {
	t.Helper()
	root := t.TempDir()
	withDir(t, root)
	record := compileRecord(idA, "monorepo", "accepted", "blocking", "2026-01-01", "", checks)
	if waiver {
		record = strings.Replace(record, "\nwaivers: []\n", "\nwaivers:\n  - reason: cutover\n    approver: Ada Lovelace\n    valid_from: 2026-01-01\n    valid_to: 2026-03-01\n", 1)
	}
	writeRepoFile(t, root, "docs/decisions/boundary.md", record)
	writeRepoFile(t, root, ".dependency-cruiser.json", cruiseRule)
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", stderr)
	}
	return root
}

func withDepcruise(t *testing.T, version, stdout string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake depcruise is a shell script")
	}
	dir := t.TempDir()
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then
  printf '%s\n' "$FAKE_DEPCRUISE_VERSION"
  exit 0
fi
if [ -n "$FAKE_DEPCRUISE_COUNT" ]; then
  printf 'x\n' >> "$FAKE_DEPCRUISE_COUNT"
fi
printf '%s' "$FAKE_DEPCRUISE_STDOUT"
`
	if err := os.WriteFile(filepath.Join(dir, "depcruise"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("FAKE_DEPCRUISE_VERSION", version)
	t.Setenv("FAKE_DEPCRUISE_STDOUT", stdout)
}

func depcruiseAt(t *testing.T, now time.Time, args []string) (string, string, int) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := run(append([]string{"check", "depcruise"}, args...), &stdout, &stderr, deps{now: func() time.Time { return now }, registry: builtin.Registry()})
	return stdout.String(), stderr.String(), code
}

func cruiseReport(violations, version string) string {
	return `{"summary":{"violations":` + violations + `,"totalCruised":2,"environment":{"version":"` + version + `"}}}`
}

const cruiseHit = `[{"from":"secret-module.ts","to":"other.ts","rule":{"name":"secret-rule","severity":"error"}}]`
