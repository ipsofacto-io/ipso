package delivery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso/internal/config"
	"github.com/ipsofacto-io/ipso/internal/edr"
)

const (
	edrA    = "01M5C5QEHHNXJ3D7X2ZCMGXQT7"
	edrB    = "01M5C5QEHHNXJ3D7X2ZCMGXQT8"
	checkA  = "0194f2a0-7b1c-7d3e-8a4f-1b2c3d4e5f60"
	checkB  = "0194f2a1-7b1c-7d3e-8a4f-1b2c3d4e5f61"
	decUUID = "0194f2a0-0000-7000-8000-000000000001"
)

var now = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

const noFloat = `package ipso.checks.generated

deny contains msg if {
	endswith(input.path, ".go")
	contains(input.added, "float64")
	msg := "no float64 for money"
}
`

const noTodo = `package ipso.checks.generated

deny contains msg if {
	contains(input.added, "TODO")
	msg := "no TODO without an issue"
}
`

func record(id, slug, status string) string {
	return fmt.Sprintf(`---
edr: 1
id: %s
slug: %s
title: %s
status: %s
owner: team:platform
scope:
  - org: acme
valid_from: 2026-01-15
valid_to: null
review_by: 2027-01-15
supersedes: []
criticality: blocking
checks: []
waivers: []
sources:
  - type: pr
    url: https://github.com/acme/platform/pull/10
tags: [fixture]
---

# %s

## Context

A fixture.

## Decision

Deliver the check.

## Alternatives considered

- None.

## Consequences

One more check.

## Verification

A test.
`, id, slug, slug, status, slug)
}

func put(t *testing.T, root, rel, text string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, root, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func exists(root, rel string) bool {
	_, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel)))
	return err == nil
}

func repoWith(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, text := range files {
		put(t, root, rel, text)
	}
	return root
}

func item(id string, edrID *string, rego string) Item {
	sum := sha256.Sum256([]byte(rego))
	digest := hex.EncodeToString(sum[:])
	return Item{ID: id, DecisionID: decUUID, EDRID: edrID, DecisionVersion: 1, VersionInForce: 1, Rego: &rego, RegoSHA256: &digest}
}

func ptr(s string) *string { return &s }

func deliver(t *testing.T, root string, items ...Item) ([]Result, []string) {
	t.Helper()
	results, problems, err := Deliver(root, config.Default(), Answer{AcceptedChecks: items}, now)
	if err != nil {
		t.Fatal(err)
	}
	return results, problems
}

const decisionFile = "docs/decisions/no-float.md"

func TestDeliverWritesTheRegoAndTheEntry(t *testing.T) {
	root := repoWith(t, map[string]string{decisionFile: record(edrA, "no-float", "accepted")})
	results, problems := deliver(t, root, item(checkA, ptr(edrA), noFloat))
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	if len(results) != 1 || results[0].Status != Added || results[0].File != decisionFile {
		t.Fatalf("results = %+v", results)
	}
	rel := ".ipso/checks/" + checkA + ".rego"
	if got := read(t, root, rel); got != noFloat {
		t.Fatalf("the Rego is not the stored Rego:\n%s", got)
	}
	doc, err := edr.ReadFile(filepath.Join(root, decisionFile))
	if err != nil || len(edr.Validate(doc)) > 0 {
		t.Fatalf("the decision file is not valid: %v %v", err, edr.Validate(doc))
	}
	rec, err := edr.RecordFrom(doc)
	if err != nil {
		t.Fatal(err)
	}
	want := edr.Check{Engine: "opa", Target: "agent-edit", Ref: rel}
	if len(rec.Checks) != 1 || rec.Checks[0] != want {
		t.Fatalf("checks = %+v", rec.Checks)
	}
	info, err := os.Stat(filepath.Join(root, decisionFile))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("the mode of the decision file changed: %v %v", info, err)
	}
	if exists(root, decisionFile+".ipso-tmp") {
		t.Fatal("a temporary file is left")
	}
}

func TestDeliverTwiceChangesNothing(t *testing.T) {
	root := repoWith(t, map[string]string{decisionFile: record(edrA, "no-float", "accepted")})
	deliver(t, root, item(checkA, ptr(edrA), noFloat))
	before := read(t, root, decisionFile)
	results, problems := deliver(t, root, item(checkA, ptr(edrA), noFloat))
	if len(problems) > 0 || len(results) != 1 || results[0].Status != Present {
		t.Fatalf("second run: %+v %v", results, problems)
	}
	if read(t, root, decisionFile) != before {
		t.Fatal("the decision file changed on the second run")
	}
}

func TestDeliverRepairsAMissingRego(t *testing.T) {
	root := repoWith(t, map[string]string{decisionFile: record(edrA, "no-float", "accepted")})
	deliver(t, root, item(checkA, ptr(edrA), noFloat))
	if err := os.Remove(filepath.Join(root, ".ipso", "checks", checkA+".rego")); err != nil {
		t.Fatal(err)
	}
	results, problems := deliver(t, root, item(checkA, ptr(edrA), noFloat))
	if len(problems) > 0 || results[0].Status != Added {
		t.Fatalf("repair: %+v %v", results, problems)
	}
	if read(t, root, ".ipso/checks/"+checkA+".rego") != noFloat {
		t.Fatal("the Rego was not written again")
	}
}

func TestDeliverTwoChecksOfOneDecisionIntoOneFile(t *testing.T) {
	root := repoWith(t, map[string]string{decisionFile: record(edrA, "no-float", "accepted")})
	results, problems := deliver(t, root, item(checkA, ptr(edrA), noFloat), item(checkB, ptr(edrA), noTodo))
	if len(problems) > 0 || len(results) != 2 {
		t.Fatalf("%+v %v", results, problems)
	}
	doc, _ := edr.ReadFile(filepath.Join(root, decisionFile))
	rec, err := edr.RecordFrom(doc)
	if err != nil || len(rec.Checks) != 2 {
		t.Fatalf("checks = %+v %v", rec.Checks, err)
	}
}

func TestDeliverHoldsACheckForAnotherVersion(t *testing.T) {
	root := repoWith(t, map[string]string{decisionFile: record(edrA, "no-float", "accepted")})
	before := read(t, root, decisionFile)
	held := Item{ID: checkA, DecisionID: decUUID, EDRID: ptr(edrA), DecisionVersion: 1, VersionInForce: 2}
	results, problems := deliver(t, root, held)
	if len(problems) > 0 || results[0].Status != Held || !strings.Contains(results[0].Detail, "version 1") {
		t.Fatalf("%+v %v", results, problems)
	}
	if exists(root, ".ipso") || read(t, root, decisionFile) != before {
		t.Fatal("a held check wrote something")
	}
}

func TestDeliverHoldsACheckThatCarriesRegoForAnotherVersion(t *testing.T) {
	root := repoWith(t, map[string]string{decisionFile: record(edrA, "no-float", "accepted")})
	stale := item(checkA, ptr(edrA), noFloat)
	stale.VersionInForce = 3
	results, problems := deliver(t, root, stale)
	if len(problems) > 0 || results[0].Status != Held || exists(root, ".ipso") {
		t.Fatalf("%+v %v", results, problems)
	}
}

func TestDeliverSkips(t *testing.T) {
	root := repoWith(t, map[string]string{
		decisionFile:            record(edrA, "no-float", "accepted"),
		"docs/decisions/old.md": record(edrB, "old", "proposed"),
	})
	before := read(t, root, decisionFile)
	results, problems := deliver(t, root,
		item(checkA, nil, noFloat),
		item(checkB, ptr("01M5C5QEHHNXJ3D7X2ZCMGXQTZ"), noTodo),
		item("0194f2a2-7b1c-7d3e-8a4f-1b2c3d4e5f62", ptr(edrB), noTodo),
	)
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	for i, want := range []string{"no EDR id", "no decision file here", "in force"} {
		if results[i].Status != Skipped || !strings.Contains(results[i].Detail, want) {
			t.Errorf("result %d = %+v, want a skip that says %q", i, results[i], want)
		}
	}
	if exists(root, ".ipso") || read(t, root, decisionFile) != before {
		t.Fatal("a skipped check wrote something")
	}
}

func TestDeliverRefusesAndWritesNothing(t *testing.T) {
	badRego := "package p\n\nallow := true\n"
	tests := []struct {
		name  string
		files map[string]string
		items func() []Item
		link  bool
		want  string
	}{
		{
			name:  "a digest that does not match",
			items: func() []Item { i := item(checkA, ptr(edrA), noFloat); i.Rego = ptr(noTodo); return []Item{i} },
			want:  "digest does not match",
		},
		{
			name:  "rego that ipso compile would refuse",
			items: func() []Item { return []Item{item(checkA, ptr(edrA), badRego)} },
			want:  "rego-no-deny",
		},
		{
			name:  "a good check next to a bad one",
			items: func() []Item { return []Item{item(checkB, ptr(edrA), noTodo), item(checkA, ptr(edrA), badRego)} },
			want:  "rego-no-deny",
		},
		{
			name:  "a file that holds other bytes",
			files: map[string]string{".ipso/checks/" + checkA + ".rego": noTodo},
			items: func() []Item { return []Item{item(checkA, ptr(edrA), noFloat)} },
			want:  "other contents",
		},
		{
			name:  "an invalid decision file elsewhere",
			files: map[string]string{"docs/decisions/broken.md": "no frontmatter\n"},
			items: func() []Item { return []Item{item(checkA, ptr(edrA), noFloat)} },
			want:  "broken.md",
		},
		{
			name:  "two decision files in force with one id",
			files: map[string]string{"docs/decisions/copy.md": record(edrA, "copy", "accepted")},
			items: func() []Item { return []Item{item(checkA, ptr(edrA), noFloat)} },
			want:  "duplicate-id",
		},
		{
			name:  "a symlinked checks directory",
			link:  true,
			items: func() []Item { return []Item{item(checkA, ptr(edrA), noFloat)} },
			want:  "symlink",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			files := map[string]string{decisionFile: record(edrA, "no-float", "accepted")}
			for rel, text := range test.files {
				files[rel] = text
			}
			root := repoWith(t, files)
			outside := t.TempDir()
			if test.link {
				if err := os.MkdirAll(filepath.Join(root, ".ipso"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(root, ".ipso", "checks")); err != nil {
					t.Skip("symlinks are not available:", err)
				}
			}
			before := read(t, root, decisionFile)
			_, problems := deliver(t, root, test.items()...)
			if len(problems) == 0 || !strings.Contains(strings.Join(problems, "\n"), test.want) {
				t.Fatalf("problems = %q, want one with %q", problems, test.want)
			}
			if read(t, root, decisionFile) != before {
				t.Fatal("a refused delivery changed the decision file")
			}
			for rel := range test.files {
				if rel == ".ipso/checks/"+checkA+".rego" && read(t, root, rel) != noTodo {
					t.Fatal("the existing file was replaced")
				}
			}
			if !test.link && exists(root, ".ipso/checks/"+checkB+".rego") {
				t.Fatal("a good check was written next to a refused one")
			}
			if entries, _ := os.ReadDir(outside); len(entries) > 0 {
				t.Fatal("a file went through the symlink")
			}
		})
	}
}

func TestDecode(t *testing.T) {
	good := item(checkA, ptr(edrA), noFloat)
	encode := func(items ...Item) string {
		raw, err := json.Marshal(Answer{AcceptedChecks: items})
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	if answer, err := Decode(strings.NewReader(encode(good))); err != nil || len(answer.AcceptedChecks) != 1 {
		t.Fatalf("a good answer: %v %v", answer, err)
	}
	if answer, err := Decode(strings.NewReader(`{"accepted_checks":[]}`)); err != nil || len(answer.AcceptedChecks) != 0 {
		t.Fatalf("an empty answer: %v %v", answer, err)
	}
	mutate := func(f func(*Item)) string { i := good; f(&i); return encode(i) }
	for name, text := range map[string]string{
		"not json":              "<html>",
		"a path as an id":       mutate(func(i *Item) { i.ID = "../../etc/passwd" }),
		"an upper case id":      mutate(func(i *Item) { i.ID = strings.ToUpper(checkA) }),
		"a bad decision id":     mutate(func(i *Item) { i.DecisionID = "x" }),
		"a bad edr id":          mutate(func(i *Item) { i.EDRID = ptr("not-a-ulid") }),
		"version zero":          mutate(func(i *Item) { i.DecisionVersion = 0 }),
		"no rego for a current": mutate(func(i *Item) { i.Rego = nil }),
		"no digest":             mutate(func(i *Item) { i.RegoSHA256 = nil }),
		"a short digest":        mutate(func(i *Item) { i.RegoSHA256 = ptr("abc") }),
		"a big rego":            mutate(func(i *Item) { big := strings.Repeat("a", 1<<20+1); i.Rego = &big }),
		"a check twice":         encode(good, good),
		"over the byte bound":   `{"accepted_checks":[],"pad":"` + strings.Repeat("a", MaxAnswerBytes) + `"}`,
	} {
		if _, err := Decode(strings.NewReader(text)); err == nil {
			t.Errorf("%s: Decode accepted it", name)
		}
	}
}
