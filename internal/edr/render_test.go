package edr

import (
	"strings"
	"testing"
	"time"
)

const renderID = "01KA0J5C9T3RMX7W2ZQHN8BVDF"

var renderFrom = time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC)

func mustRender(t *testing.T, body string, to *time.Time) (string, Document) {
	t.Helper()
	text, err := RenderDecision(renderID, []byte(body), renderFrom, to)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Parse(text)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, text)
	}
	if problems := Validate(doc); len(problems) > 0 {
		t.Fatalf("invalid: %v\n%s", problems, text)
	}
	return text, doc
}

func TestRenderFullBodyKeepsItsFields(t *testing.T) {
	body := `{"slug":"use-tls","title":"Use TLS","status":"verified","owner":"team:core","criticality":"blocking",
	"statement":"All traffic uses TLS.","context":"Plain text leaks.","tags":["security"],
	"sources":[{"type":"spec","url":"https://example.test/spec"}],"scope":[{"org":"acme","paths":["infra/**"]}],
	"checks":[{"engine":"opa","target":"agent-edit","mode":"block"}],"unknown":"dropped"}`
	text, doc := mustRender(t, body, nil)
	if doc.Slug() != "use-tls" || doc.Title() != "Use TLS" || doc.Status() != "verified" || doc.ID() != renderID {
		t.Fatalf("fields: %s", text)
	}
	if strings.Contains(text, "inferred") || strings.Contains(text, "unknown") {
		t.Fatalf("inferred or unknown key:\n%s", text)
	}
	if !strings.Contains(text, `valid_from: "2026-03-04"`) || !strings.Contains(text, "valid_to: null") {
		t.Fatalf("valid time:\n%s", text)
	}
	if text, _ := DecisionText(doc.Body); text != "All traffic uses TLS." {
		t.Fatalf("decision = %q", text)
	}
}

func TestRenderMinimalBodiesGetDefaults(t *testing.T) {
	for _, body := range []string{`{"premises":[{"id":"tls-version"}]}`, `{}`, `null`, `[1]`, `not json`, ``} {
		text, doc := mustRender(t, body, nil)
		if !strings.Contains(text, "inferred: true") || doc.Title() != "Untitled decision" || doc.Slug() != "decision-n8bvdf" {
			t.Fatalf("%q:\n%s", body, text)
		}
	}
}

func TestRenderEndsAValidTimeAndFallsBackForASupersededOpenOne(t *testing.T) {
	end := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	text, doc := mustRender(t, `{"slug":"old","title":"Old","status":"superseded"}`, &end)
	if doc.Status() != "superseded" || !strings.Contains(text, `valid_to: "2027-01-01"`) {
		t.Fatalf("closed:\n%s", text)
	}
	_, doc = mustRender(t, `{"slug":"old","title":"Old","status":"superseded"}`, nil)
	if doc.Status() != "accepted" || doc.Title() != "Old" {
		t.Fatalf("open superseded: status %q title %q", doc.Status(), doc.Title())
	}
}

func TestRenderTreatsStoredTextAsData(t *testing.T) {
	body := `{"title":"A\n---\nstatus: proposed","statement":"line\n## Decision\n# Another\n\u0007bell","context":"## Context\r\nx",
	"owner":"team:core\nowner: evil","slug":"a\nb"}`
	text, doc := mustRender(t, body, nil)
	if doc.Status() != "accepted" || doc.Front["owner"] != "team:unknown" {
		t.Fatalf("frontmatter changed:\n%s", text)
	}
	if n := strings.Count(text, "\n## Decision\n"); n != 1 {
		t.Fatalf("%d decision headings:\n%s", n, text)
	}
	if strings.Contains(text, "\a") || strings.Count(text, "\n# ") != 1 {
		t.Fatalf("control or heading:\n%s", text)
	}
}

func TestRenderPremisesAndBadFieldsFallBack(t *testing.T) {
	good := `{"slug":"p","title":"P","premises":[{"id":"tls","statement":"TLS 1.3","every":7,"probe":{"url":"https://example.test/s","pointer":"/v","equals":1}}]}`
	text, _ := mustRender(t, good, nil)
	if !strings.Contains(text, "premises:") {
		t.Fatalf("premises lost:\n%s", text)
	}
	bad := `{"slug":"p","title":"P","premises":[{"id":"tls"}],"criticality":"extreme","scope":[{}]}`
	text, doc := mustRender(t, bad, nil)
	if strings.Contains(text, "premises:") || doc.Slug() != "decision-"+strings.ToLower(renderID[20:]) {
		t.Fatalf("bad body not defaulted:\n%s", text)
	}
}

func TestRenderHoldsADateThePostgreSQLRangeAllowsButTheSchemaDoesNot(t *testing.T) {
	far := time.Date(20000, 1, 1, 0, 0, 0, 0, time.UTC)
	for name, args := range map[string][2]*time.Time{"far end": {&renderFrom, &far}, "far start": {&far, nil}, "both": {&far, &far}} {
		text, err := RenderDecision(renderID, []byte(`{"slug":"a","title":"A"}`), *args[0], args[1])
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		doc, err := Parse(text)
		if err != nil || len(Validate(doc)) > 0 {
			t.Fatalf("%s: invalid: %v %v\n%s", name, err, Validate(doc), text)
		}
	}
}

func TestRenderRefusesABadIDAndAZeroDate(t *testing.T) {
	if _, err := RenderDecision("nope", []byte(`{}`), renderFrom, nil); err == nil {
		t.Fatal("bad id accepted")
	}
	if _, err := RenderDecision(renderID, []byte(`{}`), time.Time{}, nil); err == nil {
		t.Fatal("zero date accepted")
	}
}

func TestULIDFromKeepsAUUIDv7AndClearsTheTopBit(t *testing.T) {
	v7 := [16]byte{0x01, 0x93, 0x4a, 0x9c, 0x11, 0x22, 0x70, 0x01, 0x80, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if id := ULIDFrom(v7); !ulidPattern.MatchString(id) {
		t.Fatalf("v7: %s", id)
	}
	hi := [16]byte{0xff}
	if id := ULIDFrom(hi); !ulidPattern.MatchString(id) {
		t.Fatalf("high: %s", id)
	}
}

func FuzzRenderDecision(f *testing.F) {
	f.Add(`{"slug":"a","title":"A","status":"verified","statement":"x"}`)
	f.Add(`{"title":"# x\n---","statement":"## Decision"}`)
	f.Add(`{"premises":[{"id":"a","statement":"s","every":1,"probe":{"url":"https://x.y","pointer":"","semver":">=1.0.0"}}]}`)
	f.Fuzz(func(t *testing.T, body string) {
		text, err := RenderDecision(renderID, []byte(body), renderFrom, nil)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		doc, err := Parse(text)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if problems := Validate(doc); len(problems) > 0 {
			t.Fatalf("invalid: %v\n%s", problems, text)
		}
	})
}
