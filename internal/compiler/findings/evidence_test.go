package findings

import (
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

func TestEval(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	entry := compiler.Entry{}
	artifacts := map[string][]byte{"binding.json": []byte("{\n  \"finding_id\": \"SNYK-JS-LODASH-590103\"\n}\n")}
	open := evidence(t, "snyk", "success", `"SNYK-JS-LODASH-590103","SNYK-JS-LODASH-590103"`)
	outcome := EvalCheck(entry, artifacts, open, now)
	if outcome.Err != nil || len(outcome.Violations) != 2 || !strings.Contains(outcome.Violations[0].Message, "SNYK-JS-LODASH-590103") {
		t.Fatalf("open %+v", outcome)
	}
	clean := evidence(t, "snyk", "success", "")
	if outcome = EvalCheck(entry, artifacts, clean, now); outcome.Err != nil || len(outcome.Violations) != 0 {
		t.Fatalf("clean %+v", outcome)
	}
	failed := evidence(t, "snyk", "failed", "")
	outcome = EvalCheck(entry, artifacts, failed, now)
	if compiler.CodeOf(outcome.Err) != CodeScanFailed {
		t.Fatalf("failed scan %+v", outcome)
	}
	if outcome = EvalCheck(entry, nil, failed, now); compiler.CodeOf(outcome.Err) != CodeScanFailed {
		t.Fatalf("failed scan without a binding %+v", outcome)
	}
	waived := entry
	waived.Waivers = []compiler.ManifestWaiver{{Approver: "Ada Lovelace", ValidFrom: "2026-11-01", ValidTo: "2026-12-01"}}
	outcome = EvalCheck(waived, artifacts, open, now)
	if !outcome.Waived || len(outcome.Violations) != 2 {
		t.Fatalf("waiver %+v", outcome)
	}
	outcome = EvalCheck(waived, artifacts, failed, now)
	if outcome.Err == nil || outcome.Waived {
		t.Fatalf("waiver covered an error: %+v", outcome)
	}
	if outcome = EvalCheck(entry, nil, clean, now); compiler.CodeOf(outcome.Err) != compiler.CodeBuildManifest {
		t.Fatalf("missing binding %+v", outcome)
	}
}

func TestReadEvidence(t *testing.T) {
	if _, err := ReadEvidence(strings.NewReader(`{"evidence_version":1,"tool":"wiz","status":"success","findings":[]}`), "snyk"); compiler.CodeOf(err) != CodeTool {
		t.Fatalf("tool %v", err)
	}
	if _, err := ReadEvidence(strings.NewReader(`{"evidence_version":1,"tool":"snyk","status":"success","findings":[],"path":"/tmp/pkg"}`), "snyk"); compiler.CodeOf(err) != CodeFormat {
		t.Fatalf("unknown key %v", err)
	}
	if _, err := ReadEvidence(strings.NewReader(`{"evidence_version":1,"tool":"other","status":"success","findings":[]}`), "snyk"); compiler.CodeOf(err) != CodeFormat {
		t.Fatalf("unknown tool %v", err)
	}
	if _, err := ReadEvidence(strings.NewReader(`{"evidence_version":1,"tool":"snyk","status":"running","findings":[]}`), "snyk"); compiler.CodeOf(err) != CodeFormat {
		t.Fatalf("status %v", err)
	}
	if _, err := ReadEvidence(strings.NewReader(`{"evidence_version":1,"tool":"snyk","status":"success","findings":[{"id":" ok"}]}`), "snyk"); compiler.CodeOf(err) != CodeFormat {
		t.Fatalf("id %v", err)
	}
	raw := strings.Repeat(" ", compiler.MaxRefBytes+1)
	if _, err := ReadEvidence(strings.NewReader(raw), "snyk"); compiler.CodeOf(err) != CodeTooLarge {
		t.Fatalf("size %v", err)
	}
	got, err := ReadEvidence(strings.NewReader(`{"evidence_version":1,"tool":"dependabot","status":"success","findings":[{"id":"GHSA-xxxx-xxxx-xxxx"}]}`), "dependabot")
	if err != nil || got.SHA256() == "" || len(got.Findings) != 1 {
		t.Fatalf("read %+v %v", got, err)
	}
}

func evidence(t *testing.T, tool, status, ids string) Evidence {
	t.Helper()
	var findings string
	if ids != "" {
		parts := strings.Split(ids, ",")
		quoted := make([]string, len(parts))
		for i, id := range parts {
			quoted[i] = `{"id":` + id + `}`
		}
		findings = strings.Join(quoted, ",")
	}
	raw := `{"evidence_version":1,"tool":"` + tool + `","status":"` + status + `","findings":[` + findings + `]}`
	got, err := ReadEvidence(strings.NewReader(raw), tool)
	if err != nil {
		t.Fatal(err)
	}
	return got
}
