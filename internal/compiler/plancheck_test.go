package compiler

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSelected(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	end := "2026-12-31"
	base := Entry{Engine: "opa", Target: "terraform-plan", ValidFrom: "2026-01-15"}
	if !base.Selected("", now) {
		t.Fatal("an in-force plan check should be selected")
	}
	prod := base
	prod.Env = []string{"dev", "prod"}
	if !prod.Selected("prod", now) || prod.Selected("stage", now) {
		t.Fatal("env filter")
	}
	if !prod.Selected("", now) {
		t.Fatal("no env should select every check")
	}
	expired := base
	expired.ValidTo = &end
	expired.ValidFrom = "2027-01-01"
	if expired.Selected("", now) {
		t.Fatal("a future decision should not be selected")
	}
	other := base
	other.Engine = "semgrep"
	if other.Selected("", now) {
		t.Fatal("another engine should not be selected")
	}
	repo := base
	repo.Target = ""
	if repo.Selected("", now) {
		t.Fatal("a repository policy should not be selected")
	}
}

func TestLoadBuildDigest(t *testing.T) {
	root := t.TempDir()
	id := "01M5C5QEHHNXJ3D7X2ZCMGXQT7"
	dir := filepath.Join(root, ".ipso", "build", id, "0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte("package demo\n")
	if err := os.WriteFile(filepath.Join(dir, "policy.rego"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	entry := Entry{
		DecisionID: id,
		CheckIndex: 0,
		Engine:     "opa",
		Target:     "terraform-plan",
		ValidFrom:  "2026-01-15",
		Artifacts:  []ManifestArtifact{{Name: "policy.rego", SHA256: "ec11a60fd4b8d78e363830f844d3de58fcf218682562ed7d49731620407e6737"}},
	}
	raw, err := MarshalManifest([]Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".ipso", "build", "manifest.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	build, err := LoadBuild(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(build.Entries) != 1 || build.SHA256() == "" {
		t.Fatalf("build %+v", build.Entries)
	}
	got, err := build.Artifacts(build.Entries[0])
	if err != nil || string(got["policy.rego"]) != string(body) {
		t.Fatalf("artifacts %v %v", got, err)
	}

	kept, err := build.Artifacts(build.Entries[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	again, err := build.Artifacts(build.Entries[0])
	if err != nil || string(again["policy.rego"]) != string(kept["policy.rego"]) {
		t.Fatal("evaluation would read the file a second time")
	}
	_, err = LoadBuild(root)
	if CodeOf(err) != CodeBuildDigest {
		t.Fatalf("code %q err %v", CodeOf(err), err)
	}
}

func TestLoadBuildRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "secret.rego")
	if err := os.WriteFile(secret, []byte("package outside\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".ipso", "build"), 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalManifest([]Entry{{
		DecisionID: "..",
		ValidFrom:  "2026-01-15",
		Artifacts:  []ManifestArtifact{{Name: "secret.rego", SHA256: "0"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".ipso", "build", "manifest.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = LoadBuild(root)
	if CodeOf(err) != CodeArtifactName {
		t.Fatalf("code %q err %v", CodeOf(err), err)
	}
}

func TestLoadBuildRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	elsewhere := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".ipso"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(root, ".ipso", "build")); err != nil {
		t.Fatal(err)
	}
	_, err := LoadBuild(root)
	if err == nil || CodeOf(err) != "" {
		t.Fatalf("symlink was accepted: %v", err)
	}
}

func TestLoadBuildRejectsArtifactSymlink(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "policy.rego")
	body := []byte("package demo\n")
	if err := os.WriteFile(outside, body, 0o644); err != nil {
		t.Fatal(err)
	}
	id := "01M5C5QEHHNXJ3D7X2ZCMGXQT7"
	dir := filepath.Join(root, ".ipso", "build", id, "0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "policy.rego")); err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalManifest([]Entry{{
		DecisionID: id,
		CheckIndex: 0,
		ValidFrom:  "2026-01-15",
		Artifacts:  []ManifestArtifact{{Name: "policy.rego", SHA256: "ec11a60fd4b8d78e363830f844d3de58fcf218682562ed7d49731620407e6737"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".ipso", "build", "manifest.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = LoadBuild(root)
	if CodeOf(err) != CodeArtifactName {
		t.Fatalf("code %q err %v", CodeOf(err), err)
	}
}

func TestLoadBuildRejectsBadDate(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".ipso", "build"), 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalManifest([]Entry{{
		DecisionID: "01M5C5QEHHNXJ3D7X2ZCMGXQT7",
		Engine:     "opa",
		Target:     "terraform-plan",
		ValidFrom:  "tomorrow",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".ipso", "build", "manifest.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = LoadBuild(root)
	if CodeOf(err) != CodeBuildManifest {
		t.Fatalf("code %q err %v", CodeOf(err), err)
	}
}

func TestLoadBuildMissing(t *testing.T) {
	_, err := LoadBuild(t.TempDir())
	if CodeOf(err) != CodeBuildMissing {
		t.Fatalf("code %q err %v", CodeOf(err), err)
	}
}

// The digests of a verdict are all or none (ADR-0122): the control plane reads them as the whole of the check.
func TestJudgeListsTheDigestsOfEveryViolationOrNone(t *testing.T) {
	digest := func(c byte) string { return strings.Repeat(string(c), 64) }
	entry := Entry{DecisionID: "01M5C5QEHHNXJ3D7X2ZCMGXQT7", Slug: "ebs", CheckIndex: 2, Mode: "block"}
	violation := func(fingerprint string, covered bool) Violation {
		return Violation{Fingerprint: fingerprint, Baselined: covered}
	}
	cases := []struct {
		name       string
		outcome    Outcome
		result     string
		violations int
		want       []string
	}{
		{"every violation covered", Outcome{Violations: []Violation{violation(digest('c'), true), violation(digest('a'), true)}}, "waived", 2, []string{digest('a'), digest('c')}},
		{"one uncovered", Outcome{Violations: []Violation{violation(digest('c'), true), violation(digest('b'), false)}}, "fail", 1, []string{digest('b'), digest('c')}},
		{"none covered", Outcome{Violations: []Violation{violation(digest('b'), false)}}, "fail", 1, []string{digest('b')}},
		{"one has no digest", Outcome{Violations: []Violation{violation(digest('a'), true), violation("", false)}}, "fail", 1, nil},
		{"no digest at all", Outcome{Violations: []Violation{violation("", false)}}, "fail", 1, nil},
		{"a waiver covers the check", Outcome{Waived: true, Violations: []Violation{violation(digest('a'), false)}}, "waived", 1, nil},
		{"the check failed to evaluate", Outcome{Err: errors.New("no engine"), Violations: []Violation{violation(digest('a'), false)}}, "error", 0, nil},
		{"no violation", Outcome{}, "pass", 0, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			verdict, _ := Judge(entry, c.outcome)
			if verdict.Result != c.result || verdict.Violations != c.violations || !slices.Equal(verdict.Fingerprints, c.want) {
				t.Errorf("verdict = %+v, want %s with %d violations and digests %v", verdict, c.result, c.violations, c.want)
			}
		})
	}
}

// A report writes an empty list and never null, so a version 2 verdict always has the key.
func TestAReportWritesAnEmptyListOfDigestsAndKeepsTheOrder(t *testing.T) {
	raw, err := MarshalReport(PlanReport{ReportVersion: ReportVersion, Verdicts: []Verdict{
		{DecisionID: "B", CheckIndex: 0, Result: "pass"},
		{DecisionID: "A", CheckIndex: 1, Result: "fail", Violations: 1, Fingerprints: []string{strings.Repeat("a", 64)}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "null") || strings.Count(text, `"fingerprints"`) != 2 || !strings.Contains(text, `"fingerprints": []`) || ReportVersion != 2 {
		t.Errorf("report:\n%s", text)
	}
	if strings.Index(text, `"A"`) > strings.Index(text, `"B"`) {
		t.Errorf("verdicts are not sorted by decision id:\n%s", text)
	}
}
