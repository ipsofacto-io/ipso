package eslint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

// The captures in testdata/results are real output of ESLint 10.13.0 with typescript-eslint 8.72.1,
// run the way Evaluate runs it, on the fixture subjects of testdata.

func TestParseResultsReadsRealCaptures(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name  string
		file  string
		exit  int
		rules map[string]struct{}
		mode  string
		want  []Finding
	}{
		{"clean", "clean", 0, ruleSet(floatingPromises), "block", nil},
		{"an error in block mode", "block", 1, ruleSet(floatingPromises), "block", []Finding{{Rule: floatingPromises, Path: "services/float.ts", Line: 3, Column: 3, EndLine: 3, EndColumn: 21}}},
		{"a warning in warn mode", "warn", 0, ruleSet(floatingPromises), "warn", []Finding{{Rule: floatingPromises, Path: "services/float.ts", Line: 3, Column: 3, EndLine: 3, EndColumn: 21}}},
		{"a warning in advise mode", "warn", 0, ruleSet(floatingPromises), "advise", []Finding{{Rule: floatingPromises, Path: "services/float.ts", Line: 3, Column: 3, EndLine: 3, EndColumn: 21}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseResults([]byte(capture(t, tc.file, root)), tc.exit, tc.rules, tc.mode, root)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("findings %+v", got)
			}
			for i, want := range tc.want {
				got[i].Message = ""
				if got[i] != want {
					t.Fatalf("finding %d: %+v, want %+v", i, got[i], want)
				}
			}
		})
	}
}

func TestParseResultsKeepsTheMessageForTheTerminal(t *testing.T) {
	root := t.TempDir()
	got, err := ParseResults([]byte(capture(t, "block", root)), 1, ruleSet(floatingPromises), "block", root)
	if err != nil || len(got) != 1 {
		t.Fatalf("findings %+v err %v", got, err)
	}
	line := got[0].violation().Message
	if !strings.HasPrefix(line, floatingPromises+" services/float.ts:3:3: Promises must be awaited") {
		t.Fatalf("line %q", line)
	}
}

func TestParseResultsRefusesWhatTheRunCouldNotCheck(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name string
		file string
		exit int
		mode string
		code string
		in   string
	}{
		{"a parse error", "fatal", 1, "block", CodeIncomplete, "web/bad.js: Parsing error"},
		{"a file that is in no tsconfig", "fatal-tsconfig", 1, "block", CodeIncomplete, "other.ts: Parsing error"},
		{"a suppression that hides a finding", "suppressed", 0, "block", CodeOutput, "suppression"},
		{"no file linted", "empty", 0, "block", CodeEmpty, "no file"},
		{"no file linted and exit 1", "empty", 1, "block", CodeOutput, "no results"},
		{"exit 0 with an error", "block", 0, "block", CodeOutput, "disagree"},
		{"exit 1 with no error", "clean", 1, "block", CodeOutput, "disagree"},
		{"exit 1 with only warnings", "warn", 1, "warn", CodeOutput, "disagree"},
		{"warnings in block mode", "warn", 0, "block", CodeOutput, "another mode"},
		{"errors in warn mode", "block", 1, "warn", CodeOutput, "another mode"},
		{"exit 2", "block", 2, "block", CodeRun, "status 2"},
		{"exit 137", "block", 137, "block", CodeRun, "status 137"},
		{"an unknown mode", "block", 1, "audit", CodeOutput, "audit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseResults([]byte(capture(t, tc.file, root)), tc.exit, ruleSet(floatingPromises, "eqeqeq"), tc.mode, root)
			requireCode(t, err, tc.code)
			if !strings.Contains(err.Error(), tc.in) {
				t.Fatalf("err %v, want %q", err, tc.in)
			}
		})
	}
}

func TestParseResultsRefusesAMessageOfAnotherRule(t *testing.T) {
	root := t.TempDir()
	_, err := ParseResults([]byte(capture(t, "block", root)), 1, ruleSet("eqeqeq"), "block", root)
	requireCode(t, err, CodeOutput)
}

func TestParseResultsEmptyStandardOutput(t *testing.T) {
	root := t.TempDir()
	_, err := ParseResults(nil, 0, ruleSet("eqeqeq"), "block", root)
	requireCode(t, err, CodeOutput)
	_, err = ParseResults([]byte(" \n"), 0, ruleSet("eqeqeq"), "block", root)
	requireCode(t, err, CodeOutput)
	_, err = ParseResults(nil, 1, ruleSet("eqeqeq"), "block", root)
	requireCode(t, err, CodeRun)
}

func TestParseResultsRefusesOutputThatIsNotOneList(t *testing.T) {
	root := t.TempDir()
	block := capture(t, "block", root)
	clean := capture(t, "clean", root)
	cases := map[string]string{
		"a banner before the list":   "ESLint 10.13.0\n" + block,
		"text after the list":        block + "Rule | Time (ms)\n",
		"a second list":              block + block,
		"an object":                  `{"results":[]}`,
		"not JSON":                   "[",
		"an escape byte":             "\x1b[31m" + block,
		"a null result":              "[null]",
		"a string":                   `["x"]`,
		"a result of the wrong type": `[{"filePath":7}]`,
		"a clean list with a table":  clean + "Rule   | Time (ms) | Relative\n",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseResults([]byte(raw), 1, ruleSet(floatingPromises), "block", root)
			requireCode(t, err, CodeOutput)
		})
	}
}

// edit decodes a capture, lets change edit the first result, and encodes it again.
func edit(t *testing.T, file, root string, change func(result map[string]any)) []byte {
	t.Helper()
	var results []map[string]any
	if err := json.Unmarshal([]byte(capture(t, file, root)), &results); err != nil {
		t.Fatal(err)
	}
	change(results[0])
	raw, err := json.Marshal(results)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func firstMessage(result map[string]any) map[string]any {
	return result["messages"].([]any)[0].(map[string]any)
}

func TestParseResultsRefusesResultsThatDisagreeWithThemselves(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	cases := map[string]func(result map[string]any){
		"no file path":               func(r map[string]any) { delete(r, "filePath") },
		"an empty file path":         func(r map[string]any) { r["filePath"] = "" },
		"a relative file path":       func(r map[string]any) { r["filePath"] = "services/float.ts" },
		"a file outside the root":    func(r map[string]any) { r["filePath"] = outside + "/x.ts" },
		"a path that climbs out":     func(r map[string]any) { r["filePath"] = root + "/../x.ts" },
		"the root itself":            func(r map[string]any) { r["filePath"] = root },
		"no messages":                func(r map[string]any) { delete(r, "messages") },
		"no suppressed list":         func(r map[string]any) { delete(r, "suppressedMessages") },
		"no error count":             func(r map[string]any) { delete(r, "errorCount") },
		"no warning count":           func(r map[string]any) { delete(r, "warningCount") },
		"no fatal count":             func(r map[string]any) { delete(r, "fatalErrorCount") },
		"a wrong error count":        func(r map[string]any) { r["errorCount"] = 0 },
		"a wrong warning count":      func(r map[string]any) { r["warningCount"] = 1 },
		"a wrong fatal count":        func(r map[string]any) { r["fatalErrorCount"] = 1 },
		"no rule":                    func(r map[string]any) { delete(firstMessage(r), "ruleId") },
		"a null rule":                func(r map[string]any) { firstMessage(r)["ruleId"] = nil },
		"no severity":                func(r map[string]any) { delete(firstMessage(r), "severity") },
		"severity 0":                 func(r map[string]any) { firstMessage(r)["severity"] = 0 },
		"severity 3":                 func(r map[string]any) { firstMessage(r)["severity"] = 3 },
		"no line":                    func(r map[string]any) { delete(firstMessage(r), "line") },
		"line 0":                     func(r map[string]any) { firstMessage(r)["line"] = 0 },
		"no column":                  func(r map[string]any) { delete(firstMessage(r), "column") },
		"column 0":                   func(r map[string]any) { firstMessage(r)["column"] = 0 },
		"a suppressed message":       func(r map[string]any) { r["suppressedMessages"] = []any{map[string]any{"ruleId": "eqeqeq"}} },
		"a message of another rule":  func(r map[string]any) { firstMessage(r)["ruleId"] = "no-console" },
		"a string for fatal":         func(r map[string]any) { firstMessage(r)["fatal"] = "yes" },
		"a string for the file path": func(r map[string]any) { r["filePath"] = 7 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			raw := edit(t, "block", root, change)
			_, err := ParseResults(raw, 1, ruleSet(floatingPromises), "block", root)
			requireCode(t, err, CodeOutput)
		})
	}
}

func TestParseResultsFatalNeedsNoRule(t *testing.T) {
	root := t.TempDir()
	// A parse error has no rule and no line in one of the captures, and is still only incomplete.
	_, err := ParseResults([]byte(capture(t, "fatal-tsconfig", root)), 1, ruleSet(floatingPromises), "block", root)
	requireCode(t, err, CodeIncomplete)
}

// A file that ESLint names through another spelling of the root still counts once it is resolved.
func TestParseResultsResolvesAnotherSpellingOfTheRoot(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTree(t, root, map[string]string{"services/float.ts": "x", "web/eq.js": "x"})
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(root, link); err != nil {
		t.Skipf("no symlinks: %v", err)
	}
	raw := []byte(capture(t, "block", link))
	got, err := ParseResults(raw, 1, ruleSet(floatingPromises), "block", root)
	if err != nil || len(got) != 1 || got[0].Path != "services/float.ts" {
		t.Fatalf("findings %+v err %v", got, err)
	}

	// The same spelling with no file behind it is outside the root.
	elsewhere, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseResults(raw, 1, ruleSet(floatingPromises), "block", elsewhere)
	requireCode(t, err, CodeOutput)
}

func TestViolationEscapesControlCharacters(t *testing.T) {
	f := Finding{Rule: "no-eval", Path: "web/a\x1b[31m.js", Line: 2, Column: 5, Message: "bad\nline\x07"}
	line := f.violation().Message
	if strings.ContainsAny(line, "\x1b\n\x07") {
		t.Fatalf("line %q", line)
	}
	if line != `no-eval web/a\u001b[31m.js:2:5: bad\u000aline\u0007` {
		t.Fatalf("line %q", line)
	}
}

func TestParseResultsErrorsAreCompilerErrors(t *testing.T) {
	root := t.TempDir()
	_, err := ParseResults([]byte("["), 1, ruleSet("x"), "block", root)
	if compiler.CodeOf(err) != CodeOutput {
		t.Fatalf("code %q", compiler.CodeOf(err))
	}
}
