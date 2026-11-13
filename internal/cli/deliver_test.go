package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/builtin"
	"github.com/ipsofacto-io/ipso/internal/delivery"
	"github.com/ipsofacto-io/ipso/internal/edit"
)

const (
	deliveredCheck = "0194f2a0-7b1c-7d3e-8a4f-1b2c3d4e5f60"
	otherCheck     = "0194f2a1-7b1c-7d3e-8a4f-1b2c3d4e5f61"
	decisionUUID   = "0194f2a0-0000-7000-8000-000000000001"
)

var deliverNow = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

const deliveredRego = `package ipso.checks.generated

deny contains msg if {
	endswith(input.path, ".go")
	contains(input.added, "float64")
	msg := "no float64 for money"
}
`

func answerFile(t *testing.T, items ...delivery.Item) string {
	t.Helper()
	raw, err := json.Marshal(delivery.Answer{AcceptedChecks: items})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "accepted-checks.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func acceptedItem(id, edrID, rego string) delivery.Item {
	sum := sha256.Sum256([]byte(rego))
	digest := hex.EncodeToString(sum[:])
	return delivery.Item{ID: id, DecisionID: decisionUUID, EDRID: &edrID, DecisionVersion: 1, VersionInForce: 1, Rego: &rego, RegoSHA256: &digest}
}

func runDeliver(t *testing.T, stdin string, args ...string) (string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := deliverCmd(mustGetwd(t), args, strings.NewReader(stdin), &stdout, &stderr, deps{now: func() time.Time { return deliverNow }, registry: builtin.Registry()})
	return stdout.String(), stderr.String(), code
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}

func TestDeliverThenCompileBuildsTheStoredRego(t *testing.T) {
	root := t.TempDir()
	withDir(t, root)
	writeRepoFile(t, root, "docs/decisions/no-float.md", compileRecord(idA, "no-float", "accepted", "blocking", "2026-01-15", "", ""))

	stdout, stderr, code := runDeliver(t, "", answerFile(t, acceptedItem(deliveredCheck, idA, deliveredRego)))
	if code != 0 || !strings.Contains(stdout, "added check "+deliveredCheck) || stderr != "" {
		t.Fatalf("deliver = %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	out, errOut, code := compileAt(t, deliverNow, builtin.Registry())
	if code != 0 {
		t.Fatalf("compile = %d\n%s\n%s", code, out, errOut)
	}
	if got := readBuild(t, root, idA+"/0/policy.rego"); got != deliveredRego {
		t.Fatalf("the built Rego is not the stored Rego:\n%s", got)
	}
	build, err := compiler.LoadBuild(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(build.Entries) != 1 || build.Entries[0].Target != edit.Target || build.Entries[0].Engine != "opa" {
		t.Fatalf("manifest = %+v", build.Entries)
	}
	results, err := edit.Evaluate(build, []edit.Proposal{{Tool: "write", Path: "pay/money.go", Added: "var total float64"}}, "", deliverNow)
	if err != nil || len(results) != 1 || len(results[0].Outcome.Violations) != 1 {
		t.Fatalf("the check did not deny a float64 edit: %+v %v", results, err)
	}
	results, err = edit.Evaluate(build, []edit.Proposal{{Tool: "write", Path: "pay/money.go", Added: "var total int64"}}, "", deliverNow)
	if err != nil || len(results) != 1 || len(results[0].Outcome.Violations) != 0 {
		t.Fatalf("the check denied an edit it should allow: %+v %v", results, err)
	}

	stdout, _, code = runDeliver(t, "", answerFile(t, acceptedItem(deliveredCheck, idA, deliveredRego)))
	if code != 0 || !strings.Contains(stdout, "already delivered") {
		t.Fatalf("second deliver = %d, %q", code, stdout)
	}
}

func TestDeliverReadsStdin(t *testing.T) {
	root := t.TempDir()
	withDir(t, root)
	writeRepoFile(t, root, "docs/decisions/no-float.md", compileRecord(idA, "no-float", "accepted", "blocking", "2026-01-15", "", ""))
	raw, err := os.ReadFile(answerFile(t, acceptedItem(deliveredCheck, idA, deliveredRego)))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, code := runDeliver(t, string(raw), "-"); code != 0 {
		t.Fatalf("deliver - = %d", code)
	}
	if _, err := os.Stat(filepath.Join(root, ".ipso", "checks", deliveredCheck+".rego")); err != nil {
		t.Fatal(err)
	}
}

func TestDeliverSaysWhatItHeldAndSkipped(t *testing.T) {
	root := t.TempDir()
	withDir(t, root)
	writeRepoFile(t, root, "docs/decisions/no-float.md", compileRecord(idA, "no-float", "accepted", "blocking", "2026-01-15", "", ""))
	held := acceptedItem(deliveredCheck, idA, deliveredRego)
	held.VersionInForce = 2
	held.Rego, held.RegoSHA256 = nil, nil
	away := acceptedItem(otherCheck, idC, deliveredRego)
	stdout, stderr, code := runDeliver(t, "", answerFile(t, held, away))
	if code != 0 || stdout != "" {
		t.Fatalf("deliver = %d, stdout %q", code, stdout)
	}
	for _, want := range []string{"check " + deliveredCheck + ": held, it was accepted for version 1", "check " + otherCheck + ": skipped, no decision file here has the id " + idC} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	if _, err := os.Stat(filepath.Join(root, ".ipso")); err == nil {
		t.Fatal("a held or skipped check wrote something")
	}
}

func TestDeliverRefusesBeforeItWrites(t *testing.T) {
	root := t.TempDir()
	withDir(t, root)
	writeRepoFile(t, root, "docs/decisions/no-float.md", compileRecord(idA, "no-float", "accepted", "blocking", "2026-01-15", "", ""))
	before, err := os.ReadFile(filepath.Join(root, "docs/decisions/no-float.md"))
	if err != nil {
		t.Fatal(err)
	}
	bad := acceptedItem(otherCheck, idA, "package p\n\nallow := true\n")
	good := acceptedItem(deliveredCheck, idA, deliveredRego)
	_, stderr, code := runDeliver(t, "", answerFile(t, good, bad))
	if code != 1 || !strings.Contains(stderr, "rego-no-deny") || !strings.Contains(stderr, "nothing was delivered") {
		t.Fatalf("deliver = %d, stderr %q", code, stderr)
	}
	after, _ := os.ReadFile(filepath.Join(root, "docs/decisions/no-float.md"))
	if !bytes.Equal(before, after) {
		t.Fatal("the decision file changed")
	}
	if _, err := os.Stat(filepath.Join(root, ".ipso")); err == nil {
		t.Fatal("a refused delivery wrote a file")
	}
}

func TestDeliverUsageAndInput(t *testing.T) {
	root := t.TempDir()
	withDir(t, root)
	for _, args := range [][]string{nil, {""}, {"a", "b"}} {
		if _, stderr, code := runDeliver(t, "", args...); code != 2 || !strings.Contains(stderr, "usage: ipso deliver") {
			t.Errorf("deliver %q = %d, %q", args, code, stderr)
		}
	}
	if _, _, code := runDeliver(t, "", filepath.Join(root, "missing.json")); code != 1 {
		t.Errorf("a missing file = %d, want 1", code)
	}
	if _, stderr, code := runDeliver(t, "<html>", "-"); code != 1 || !strings.Contains(stderr, "not JSON") {
		t.Errorf("a malformed answer = %d, %q", code, stderr)
	}
	if stdout, _, code := runDeliver(t, `{"accepted_checks":[]}`, "-"); code != 0 || !strings.Contains(stdout, "no accepted checks") {
		t.Errorf("an empty answer = %d, %q", code, stdout)
	}
}
