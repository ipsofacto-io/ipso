package sarif

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/sarif/sariftest"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func entry(index int, mode string) compiler.Entry {
	return compiler.Entry{
		DecisionID: "01HZZZZZZZZZZZZZZZZZZZZZZZ",
		Slug:       "tls-on-ingress",
		Path:       "docs/decisions/tls.md",
		Title:      "Public ingress must terminate TLS",
		CheckIndex: index,
		Mode:       mode,
	}
}

func located(path string, line int) compiler.Violation {
	return compiler.Violation{
		Message:  "engine text",
		Position: &compiler.Position{Path: path, StartLine: line, StartColumn: 3, EndLine: line, EndColumn: 9},
	}
}

func TestGolden(t *testing.T) {
	violations := []compiler.Violation{{Message: "engine text", Address: "aws_s3_bucket.private"}, {Message: "more engine text"}}
	cases := []struct {
		name   string
		checks []Check
	}{
		{"empty", nil},
		{"pass", []Check{{Entry: entry(0, "block")}}},
		{"modes", []Check{
			{Entry: entry(0, "block"), Outcome: compiler.Outcome{Violations: violations}},
			{Entry: entry(1, "warn"), Outcome: compiler.Outcome{Violations: violations[:1]}},
			{Entry: entry(2, "advise"), Outcome: compiler.Outcome{Violations: violations}},
		}},
		{"waived", []Check{{Entry: entry(0, "block"), Outcome: compiler.Outcome{Violations: violations, Waived: true}}}},
		{"error", []Check{{Entry: entry(0, "block"), Outcome: compiler.Outcome{Err: &compiler.Error{Code: "semgrep-run", Err: errors.New("engine text")}}}}},
		{"located", []Check{{Entry: entry(0, "warn"), Outcome: compiler.Outcome{Violations: []compiler.Violation{
			located("src/b file.py", 9),
			located("src/a.py", 7),
			located("src/a.py", 2),
		}}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := Marshal("1.2.3", "semgrep", tc.checks)
			if err != nil {
				t.Fatal(err)
			}
			sariftest.Validate(t, raw)
			if strings.Contains(string(raw), "engine text") || strings.Contains(string(raw), "aws_s3_bucket") {
				t.Fatalf("engine output leaked: %s", raw)
			}
			path := filepath.Join("testdata", tc.name+".sarif")
			if *update {
				if err := os.WriteFile(path, raw, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(raw, want) {
				t.Fatalf("got\n%s\nwant\n%s", raw, want)
			}
		})
	}
}

func TestErrorWithoutCodeIsGeneric(t *testing.T) {
	raw, err := Marshal("1.2.3", "plan", []Check{{Entry: entry(0, "block"), Outcome: compiler.Outcome{Err: errors.New("secret text")}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret text") || !strings.Contains(string(raw), genericErrorCode) {
		t.Fatalf("output %s", raw)
	}
	if decode(t, raw).Runs[0].Invocations[0].ExecutionSuccessful {
		t.Fatal("a check error must mark the run unsuccessful")
	}
}

func TestHostileValuesAreEscaped(t *testing.T) {
	hostile := entry(0, "block")
	hostile.Title = "x](https://evil.test) ![img](y) <b>@team\nsecond"
	hostile.Slug = "bad`slug"
	raw, err := Marshal("1.2.3", "plan", []Check{{Entry: hostile, Outcome: compiler.Outcome{Violations: []compiler.Violation{{Message: "m"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	sariftest.Validate(t, raw)
	got := decode(t, raw).Runs[0]
	if text := got.Results[0].Message.Text; !strings.HasPrefix(text, `x\](https://evil.test) !\[img\](y)`) {
		t.Fatalf("message %q", text)
	}
	help := got.Tool.Driver.Rules[0].Help.Markdown
	for _, want := range []string{`x\]\(https\://evil\.test\)`, `\!\[img\]\(y\)`, `\<b\>\@team`} {
		if !strings.Contains(help, want) {
			t.Fatalf("help %q does not contain %q", help, want)
		}
	}
	if strings.Contains(help, "ipso explain") || strings.Contains(got.Tool.Driver.Rules[0].Help.Text, "ipso explain") {
		t.Fatalf("an unsafe slug reached the command: %q", help)
	}
	if strings.ContainsAny(got.Results[0].Message.Text, "\n") {
		t.Fatalf("message has a line break: %q", got.Results[0].Message.Text)
	}
}

func TestColonCannotBecomeAScheme(t *testing.T) {
	raw, err := Marshal("1.2.3", "semgrep", []Check{{Entry: entry(0, "block"), Outcome: compiler.Outcome{Violations: []compiler.Violation{located("c:foo.py", 3)}}}})
	if err != nil {
		t.Fatal(err)
	}
	if uri := decode(t, raw).Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI; uri != "c%3Afoo.py" {
		t.Fatalf("uri %q", uri)
	}
}

func TestLongValuesAreLimited(t *testing.T) {
	long := entry(0, "block")
	long.Title = strings.Repeat("é", 3000)
	long.Slug = strings.Repeat("a", 300)
	raw, err := Marshal("1.2.3", "plan", []Check{{Entry: long, Outcome: compiler.Outcome{Violations: []compiler.Violation{{Message: "m"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	rule := decode(t, raw).Runs[0].Tool.Driver.Rules[0]
	if len([]rune(rule.Help.Text)) > 2*maxDescriptionRunes || len([]rune(rule.Name)) != maxNameRunes || len([]rune(rule.ShortDescription.Text)) != maxDescriptionRunes || len([]rune(rule.FullDescription.Text)) != maxDescriptionRunes {
		t.Fatalf("limits: name %d short %d full %d", len([]rune(rule.Name)), len([]rune(rule.ShortDescription.Text)), len([]rune(rule.FullDescription.Text)))
	}
}

func TestUnsafePositionFallsBackToDecision(t *testing.T) {
	for _, path := range []string{"../outside.py", "/etc/passwd", `a\b.py`, ".", ""} {
		raw, err := Marshal("1.2.3", "semgrep", []Check{{Entry: entry(0, "block"), Outcome: compiler.Outcome{Violations: []compiler.Violation{located(path, 3)}}}})
		if err != nil {
			t.Fatal(err)
		}
		got := decode(t, raw).Runs[0].Results[0].Locations[0].PhysicalLocation
		if got.ArtifactLocation.URI != "docs/decisions/tls.md" || got.Region.StartLine != 1 {
			t.Fatalf("%q: location %+v", path, got)
		}
	}
}

func TestRegionFallsBackToStart(t *testing.T) {
	cases := []struct {
		in   compiler.Position
		want region
	}{
		{compiler.Position{StartLine: 4}, region{4, 1, 4, 2}},
		{compiler.Position{StartLine: 4, StartColumn: 3}, region{4, 3, 4, 4}},
		{compiler.Position{StartLine: 4, StartColumn: 3, EndLine: 2, EndColumn: 9}, region{4, 3, 4, 4}},
		{compiler.Position{StartLine: 4, StartColumn: 3, EndLine: 4, EndColumn: 3}, region{4, 3, 4, 4}},
		{compiler.Position{StartLine: 4, StartColumn: 3, EndLine: 6, EndColumn: 1}, region{4, 3, 6, 1}},
	}
	for _, tc := range cases {
		if got := regionOf(tc.in); got != tc.want {
			t.Fatalf("%+v: got %+v want %+v", tc.in, got, tc.want)
		}
	}
}

func TestMissingManifestFieldsFail(t *testing.T) {
	for _, change := range []func(*compiler.Entry){
		func(e *compiler.Entry) { e.Path = "" },
		func(e *compiler.Entry) { e.Title = "" },
		func(e *compiler.Entry) { e.Path = "../outside.md" },
	} {
		bad := entry(0, "block")
		change(&bad)
		_, err := Marshal("1.2.3", "plan", []Check{{Entry: bad}})
		if compiler.CodeOf(err) != compiler.CodeBuildManifest {
			t.Fatalf("err %v", err)
		}
	}
}

func TestTruncationKeepsTheMostSevere(t *testing.T) {
	var checks []Check
	var notes []compiler.Violation
	for i := 0; i < maxResults; i++ {
		notes = append(notes, located(fmt.Sprintf("src/%d.py", i), 1))
	}
	checks = append(checks, Check{Entry: entry(0, "advise"), Outcome: compiler.Outcome{Violations: notes}})
	checks = append(checks, Check{Entry: entry(1, "block"), Outcome: compiler.Outcome{Violations: []compiler.Violation{located("src/block.py", 1)}}})
	raw, err := Marshal("1.2.3", "semgrep", checks)
	if err != nil {
		t.Fatal(err)
	}
	got := decode(t, raw).Runs[0]
	if len(got.Results) != maxResults {
		t.Fatalf("results %d", len(got.Results))
	}
	if got.Results[len(got.Results)-1].Level != levelError {
		t.Fatalf("the block finding was dropped")
	}
	notices := got.Invocations[0].ToolExecutionNotifications
	if len(notices) != 1 || !strings.HasPrefix(notices[0].Message.Text, "Results omitted: 1.") {
		t.Fatalf("notifications %+v", notices)
	}
}

func decode(t *testing.T, raw []byte) log {
	t.Helper()
	var out log
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
