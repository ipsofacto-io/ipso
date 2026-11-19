package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/builtin"
)

func TestCheckFindings(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	withDir(t, root)
	marker := "secret/pkg/left-pad"
	record := compileRecord(idA, "lodash", "accepted", "blocking", "2026-11-01", "", "  - engine: snyk\n    ref: "+marker+"\n")
	writeRepoFile(t, root, "docs/decisions/lodash.md", record)
	if _, stderr, code := compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile: %s", stderr)
	}
	writeRepoFile(t, root, "evidence.json", findingEvidence("snyk", "success", marker, marker))
	report := filepath.Join(root, "report.json")
	sarifPath := filepath.Join(root, "out.sarif")
	stdout, stderr, code := findingAt(t, now, "snyk", []string{"evidence.json", "--report", report, "--sarif", sarifPath})
	if code != 1 || strings.Count(stdout, marker) != 2 {
		t.Fatalf("fail code %d\n%s\n%s", code, stdout, stderr)
	}
	body, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	sarifBody, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), marker) || strings.Contains(string(sarifBody), marker) || strings.Contains(string(body), "open finding") {
		t.Fatalf("report or SARIF carries the finding\n%s\n%s", body, sarifBody)
	}
	var decoded compiler.FindingsReport
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ReportVersion != 2 || len(decoded.EvidenceSHA256) != 64 || decoded.Verdicts[0].Violations != 2 || decoded.Verdicts[0].Result != "fail" || len(decoded.Verdicts[0].Fingerprints) != 0 || !strings.Contains(string(body), `"fingerprints": []`) {
		t.Fatalf("report %+v", decoded)
	}

	writeRepoFile(t, root, "evidence.json", findingEvidence("snyk", "success"))
	stdout, stderr, code = findingAt(t, now, "snyk", []string{"evidence.json"})
	if code != 0 || !strings.Contains(stdout, "pass") {
		t.Fatalf("clean code %d\n%s\n%s", code, stdout, stderr)
	}

	writeRepoFile(t, root, "evidence.json", findingEvidence("wiz", "success"))
	stdout, stderr, code = findingAt(t, now, "snyk", []string{"evidence.json"})
	if code != 1 || !strings.Contains(stderr, "evidence-tool") {
		t.Fatalf("tool code %d\n%s\n%s", code, stdout, stderr)
	}

	writeRepoFile(t, root, "evidence.json", `{"evidence_version":1,"tool":"snyk","status":"success","findings":[],"path":"/tmp/pkg"}`)
	if _, stderr, code = findingAt(t, now, "snyk", []string{"evidence.json"}); code != 1 || !strings.Contains(stderr, "evidence-format") {
		t.Fatalf("format code %d %s", code, stderr)
	}

	warned := compileRecord(idA, "lodash", "accepted", "warning", "2026-11-01", "", "  - engine: snyk\n    ref: "+marker+"\n    mode: warn\n")
	writeRepoFile(t, root, "docs/decisions/lodash.md", warned)
	writeRepoFile(t, root, "evidence.json", findingEvidence("snyk", "success", marker))
	if _, stderr, code = compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile warn: %s", stderr)
	}
	stdout, _, code = findingAt(t, now, "snyk", []string{"evidence.json"})
	if code != 0 || !strings.Contains(stdout, "(warn):") || !strings.Contains(stdout, marker) {
		t.Fatalf("warn code %d\n%s", code, stdout)
	}

	waived := compileRecord(idA, "lodash", "accepted", "blocking", "2026-11-01", "", "  - engine: snyk\n    ref: "+marker+"\n")
	waived = strings.Replace(waived, "\nwaivers: []\n", "\nwaivers:\n  - reason: cutover\n    approver: Ada Lovelace\n    valid_from: 2026-11-01\n    valid_to: 2026-12-01\n", 1)
	writeRepoFile(t, root, "docs/decisions/lodash.md", waived)
	if _, stderr, code = compileAt(t, now, builtin.Registry()); code != 0 {
		t.Fatalf("compile waiver: %s", stderr)
	}
	stdout, stderr, code = findingAt(t, now, "snyk", []string{"evidence.json"})
	if code != 0 || !strings.Contains(stdout, "waived") || strings.Contains(stdout, marker) {
		t.Fatalf("waiver code %d\n%s\n%s", code, stdout, stderr)
	}
	writeRepoFile(t, root, "evidence.json", findingEvidence("snyk", "failed"))
	stdout, stderr, code = findingAt(t, now, "snyk", []string{"evidence.json"})
	if code != 1 || !strings.Contains(stdout, "scan-failed") || strings.Contains(stdout, "waived") || strings.Contains(stdout, marker) {
		t.Fatalf("failed scan code %d\n%s\n%s", code, stdout, stderr)
	}

	var out, errOut strings.Builder
	if code := run([]string{"baseline", "create", "snyk", "evidence.json"}, &out, &errOut, deps{now: func() time.Time { return now }, registry: builtin.Registry()}); code != 2 {
		t.Fatalf("baseline code %d %s", code, errOut.String())
	}
}

func findingEvidence(tool, status string, ids ...string) string {
	items := make([]string, len(ids))
	for i, id := range ids {
		items[i] = `{"id":"` + id + `"}`
	}
	return `{"evidence_version":1,"tool":"` + tool + `","status":"` + status + `","findings":[` + strings.Join(items, ",") + `]}`
}

func findingAt(t *testing.T, now time.Time, tool string, args []string) (string, string, int) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := run(append([]string{"check", tool}, args...), &stdout, &stderr, deps{now: func() time.Time { return now }, registry: builtin.Registry()})
	return stdout.String(), stderr.String(), code
}
