package baseline

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

const testSalt = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func testEntry() compiler.Entry {
	return compiler.Entry{DecisionID: "01HZZZZZZZZZZZZZZZZZZZZZZZ", CheckIndex: 2, Engine: "semgrep", Slug: "no-eval", Mode: "block"}
}

func violation(fields ...string) compiler.Violation {
	return compiler.Violation{Message: "m", Identity: fields}
}

// The digest is a contract with stored server rows (ADR-0052, ADR-0059). A change here is a new domain string.
func TestFingerprintVector(t *testing.T) {
	got, err := Fingerprints(testSalt, testEntry(), Scope{Env: "prod", Input: "stack-a"}, []compiler.Violation{violation("no-eval", "src/a.py"), violation("no-eval", "src/a.py")})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"0af8ff879ee11e44114b72292126dfd1f0b5f4200c06087ba6233939879d92ec",
		"ef06aebc27d5f8f08f91d799b87a59e7300d7dd12adc9a478f53a89374c2d570",
	}
	if got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %q", got)
	}
}

func TestFingerprintsAreDistinct(t *testing.T) {
	base := testEntry()
	otherIndex := base
	otherIndex.CheckIndex = 3
	otherDecision := base
	otherDecision.DecisionID = "01HZZZZZZZZZZZZZZZZZZZZZZY"
	otherEngine := base
	otherEngine.Engine = "eslint"
	cases := []struct {
		entry compiler.Entry
		salt  string
		scope Scope
		v     compiler.Violation
	}{
		{base, testSalt, Scope{}, violation("a", "b")},
		{otherIndex, testSalt, Scope{}, violation("a", "b")},
		{otherDecision, testSalt, Scope{}, violation("a", "b")},
		{otherEngine, testSalt, Scope{}, violation("a", "b")},
		{base, strings.Repeat("ab", 32), Scope{}, violation("a", "b")},
		{base, testSalt, Scope{}, violation("ab", "")},
		{base, testSalt, Scope{}, violation("", "ab")},
		{base, testSalt, Scope{}, violation("a", "c")},
		{base, testSalt, Scope{Env: "prod"}, violation("a", "b")},
		{base, testSalt, Scope{Input: "prod"}, violation("a", "b")},
		{base, testSalt, Scope{Env: "prod", Input: "stack"}, violation("a", "b")},
		{base, testSalt, Scope{Env: "stack", Input: "prod"}, violation("a", "b")},
	}
	seen := map[string]int{}
	for i, tc := range cases {
		got, err := Fingerprints(tc.salt, tc.entry, tc.scope, []compiler.Violation{tc.v})
		if err != nil {
			t.Fatal(err)
		}
		if !compiler.ValidDigest(got[0]) {
			t.Fatalf("digest %q", got[0])
		}
		if prev, ok := seen[got[0]]; ok {
			t.Fatalf("cases %d and %d share a digest", prev, i)
		}
		seen[got[0]] = i
	}
}

func TestFingerprintsNumberRepeatsAndSkipNilIdentity(t *testing.T) {
	got, err := Fingerprints(testSalt, testEntry(), Scope{}, []compiler.Violation{
		violation("r", "a"), {Message: "cannot"}, violation("r", "a"), violation("r", "b"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got[1] != "" || got[0] == "" || got[0] == got[2] || got[3] == got[0] {
		t.Fatalf("got %q", got)
	}
	only, err := Fingerprints(testSalt, testEntry(), Scope{}, []compiler.Violation{violation("r", "b")})
	if err != nil {
		t.Fatal(err)
	}
	if only[0] != got[3] {
		t.Fatal("another identity changed the occurrence number")
	}
}

func TestApply(t *testing.T) {
	entry := testEntry()
	three := []compiler.Violation{violation("r", "a"), violation("r", "a"), violation("r", "a")}
	digests, err := Fingerprints(testSalt, entry, Scope{}, three)
	if err != nil {
		t.Fatal(err)
	}
	entry.Baseline = &compiler.ManifestBaseline{Salt: testSalt, Fingerprints: digests[:2]}

	got, err := Apply(entry, Scope{}, compiler.Outcome{Violations: three})
	if err != nil {
		t.Fatal(err)
	}
	covered := 0
	for _, item := range got.Violations {
		if item.Baselined {
			covered++
		}
	}
	if covered != 2 {
		t.Fatalf("a baseline of 2 repeats covered %d of 3", covered)
	}
	if three[0].Baselined {
		t.Fatal("Apply changed the caller's violations")
	}

	failure := errors.New("engine failed")
	got, err = Apply(entry, Scope{}, compiler.Outcome{Violations: three, Err: failure})
	if err != nil || got.Err != failure || got.Violations[0].Baselined {
		t.Fatalf("an error must stay an error: %+v %v", got, err)
	}
	got, err = Apply(entry, Scope{}, compiler.Outcome{Violations: three, Waived: true})
	if err != nil || !got.Waived || got.Violations[0].Baselined {
		t.Fatalf("a waiver must keep the check: %+v %v", got, err)
	}
	cannot, err := Apply(entry, Scope{}, compiler.Outcome{Violations: []compiler.Violation{{Message: "job not in evidence"}}})
	if err != nil || cannot.Violations[0].Baselined {
		t.Fatalf("a violation without identity must stay: %+v %v", cannot, err)
	}
	other, err := Apply(entry, Scope{Env: "prod"}, compiler.Outcome{Violations: three})
	if err != nil || other.Violations[0].Baselined {
		t.Fatalf("another scope must match nothing: %+v %v", other, err)
	}
	bare := testEntry()
	got, err = Apply(bare, Scope{}, compiler.Outcome{Violations: three})
	if err != nil || got.Violations[0].Baselined {
		t.Fatalf("no baseline must cover nothing: %+v %v", got, err)
	}
}

func goodFile() string {
	return `{"baseline_version":1,"salt":"` + testSalt + `","checks":[{"decision_id":"a","check_index":0,"fingerprints":["` + strings.Repeat("a", 64) + `"]}]}`
}

func TestParseRefuses(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for name, raw := range map[string]string{
		"not json":             `nope`,
		"unknown field":        `{"baseline_version":1,"salt":"` + testSalt + `","checks":[],"extra":1}`,
		"trailing data":        goodFile() + `{}`,
		"wrong version":        `{"baseline_version":2,"salt":"` + testSalt + `","checks":[]}`,
		"short salt":           `{"baseline_version":1,"salt":"ab","checks":[]}`,
		"upper salt":           `{"baseline_version":1,"salt":"` + strings.ToUpper(testSalt) + `","checks":[]}`,
		"bad digest":           `{"baseline_version":1,"salt":"` + testSalt + `","checks":[{"decision_id":"a","check_index":0,"fingerprints":["zz"]}]}`,
		"no decision":          `{"baseline_version":1,"salt":"` + testSalt + `","checks":[{"decision_id":"","check_index":0,"fingerprints":[]}]}`,
		"negative index":       `{"baseline_version":1,"salt":"` + testSalt + `","checks":[{"decision_id":"a","check_index":-1,"fingerprints":[]}]}`,
		"check twice":          `{"baseline_version":1,"salt":"` + testSalt + `","checks":[{"decision_id":"a","check_index":0,"fingerprints":[]},{"decision_id":"a","check_index":0,"fingerprints":[]}]}`,
		"bad input name":       `{"baseline_version":1,"salt":"` + testSalt + `","checks":[{"decision_id":"a","check_index":0,"input":"a/b","fingerprints":[]}]}`,
		"scope twice":          `{"baseline_version":1,"salt":"` + testSalt + `","checks":[{"decision_id":"a","check_index":0,"env":"p","fingerprints":[]},{"decision_id":"a","check_index":0,"env":"p","fingerprints":[]}]}`,
		"repeat in a check":    `{"baseline_version":1,"salt":"` + testSalt + `","checks":[{"decision_id":"a","check_index":0,"fingerprints":["` + digest + `","` + digest + `"]}]}`,
		"repeat in a decision": `{"baseline_version":1,"salt":"` + testSalt + `","checks":[{"decision_id":"a","check_index":0,"fingerprints":["` + digest + `"]},{"decision_id":"a","check_index":1,"fingerprints":["` + digest + `"]}]}`,
	} {
		if _, err := Parse([]byte(raw)); compiler.CodeOf(err) != CodeFile {
			t.Fatalf("%s: err %v", name, err)
		}
	}
	if _, err := Parse([]byte(goodFile())); err != nil {
		t.Fatal(err)
	}
}

func TestOneCheckHoldsOneEntryPerScope(t *testing.T) {
	raw := `{"baseline_version":1,"salt":"` + testSalt + `","checks":[{"decision_id":"a","check_index":0,"env":"prod","fingerprints":[]},{"decision_id":"a","check_index":0,"env":"staging","fingerprints":[]},{"decision_id":"a","check_index":0,"input":"prod","fingerprints":[]}]}`
	file, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if file.Find("a", 0, Scope{Env: "staging"}) != 1 || file.Find("a", 0, Scope{Input: "prod"}) != 2 || file.Find("a", 0, Scope{}) != -1 {
		t.Fatalf("file %+v", file)
	}
}

func TestValidInput(t *testing.T) {
	for _, good := range []string{"a", "stack-a", "A.b_c-1", strings.Repeat("a", 64)} {
		if !ValidInput(good) {
			t.Fatalf("%q", good)
		}
	}
	for _, bad := range []string{"", "-a", ".a", "a/b", "a b", "a\n", strings.Repeat("a", 65)} {
		if ValidInput(bad) {
			t.Fatalf("%q", bad)
		}
	}
}

func TestDecisionCapCountsEveryCheck(t *testing.T) {
	file := File{Version: fileVersion, Salt: testSalt}
	half := compiler.MaxBaselineFingerprints/2 + 1
	for index := range 2 {
		digests := make([]string, 0, half)
		for i := range half {
			digests = append(digests, digestOf(index, i))
		}
		file.Checks = append(file.Checks, Check{DecisionID: "a", CheckIndex: index, Fingerprints: digests})
	}
	if _, err := file.Marshal(); compiler.CodeOf(err) != CodeFile {
		t.Fatalf("err %v", err)
	}
}

func digestOf(index, i int) string {
	digests, _ := Fingerprints(testSalt, compiler.Entry{DecisionID: "a", CheckIndex: index}, Scope{}, []compiler.Violation{violation(strconv.Itoa(i))})
	return digests[0]
}

func TestMarshalIsDeterministic(t *testing.T) {
	low, high := strings.Repeat("a", 64), strings.Repeat("b", 64)
	file := File{Salt: testSalt, Checks: []Check{
		{DecisionID: "b", CheckIndex: 0, Fingerprints: []string{}},
		{DecisionID: "a", CheckIndex: 1, Fingerprints: []string{high, low}},
		{DecisionID: "a", CheckIndex: 0, Fingerprints: []string{}},
	}}
	raw, err := file.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if back.Checks[0].CheckIndex != 0 || back.Checks[1].Fingerprints[0] != low || back.Checks[2].DecisionID != "b" {
		t.Fatalf("order %+v", back.Checks)
	}
	if !strings.Contains(string(raw), low+"\",\n") {
		t.Fatalf("fingerprints are not one per line:\n%s", raw)
	}
}

func TestReadFile(t *testing.T) {
	root := t.TempDir()
	if _, found, err := Read(root); found || err != nil {
		t.Fatalf("missing: %v %v", found, err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".ipso"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, found, err := Read(root); found || err != nil {
		t.Fatalf("missing file: %v %v", found, err)
	}
	path := filepath.Join(root, filepath.FromSlash(RelPath))
	if err := os.WriteFile(path, []byte(goodFile()), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, found, err := Read(root); !found || err != nil {
		t.Fatalf("good: %v %v", found, err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat(" ", maxFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Read(root); compiler.CodeOf(err) != CodeFile {
		t.Fatalf("oversize: %v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(target, []byte(goodFile()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Read(root); compiler.CodeOf(err) != CodeFile {
		t.Fatalf("symlink: %v", err)
	}
}

func TestNewSaltsDiffer(t *testing.T) {
	one, err := New()
	if err != nil {
		t.Fatal(err)
	}
	two, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if one.Salt == two.Salt || !compiler.ValidDigest(one.Salt) {
		t.Fatalf("salts %q %q", one.Salt, two.Salt)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(goodFile()))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		file, err := Parse(raw)
		if err != nil {
			return
		}
		if _, err := file.Marshal(); err != nil {
			t.Fatalf("a parsed file did not marshal: %v", err)
		}
	})
}
