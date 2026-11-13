package edr

import (
	"reflect"
	"strings"
	"testing"
)

const addCheckBody = `
# Keep the float out of money

## Context

A float lost a cent.

## Decision

No float for money.

## Alternatives considered

- Round at the edge.

## Consequences

Amounts are integers.

## Verification

A check denies the edit.
`

func addCheckRecord(checks string) string {
	return `---
edr: 1
id: 01M5C5QEHHNXJ3D7X2ZCMGXQT7
slug: no-float-money
title: "No float for money"
status: accepted
owner: team:platform
scope:
  - org: acme
valid_from: 2026-01-15
valid_to: null
review_by: 2026-07-15
supersedes: []
criticality: blocking # a comment that stays
` + checks + `waivers: []
sources:
  - type: pr
    url: https://github.com/acme/platform/pull/10
tags: [money]
---
` + addCheckBody
}

var agentEdit = Check{Engine: "opa", Target: "agent-edit", Ref: ".ipso/checks/0194f2a0.rego"}

func TestAddCheckToAnEmptyFlowList(t *testing.T) {
	in := addCheckRecord("checks: []\n")
	out, added, err := AddCheck(in, agentEdit)
	if err != nil || !added {
		t.Fatalf("AddCheck() = %v, %v", added, err)
	}
	if !strings.Contains(out, "checks:\n  - engine: opa\n    target: agent-edit\n    ref: .ipso/checks/0194f2a0.rego\n") {
		t.Fatalf("the check is not a block item:\n%s", out)
	}
	if !strings.Contains(out, "criticality: blocking # a comment that stays\n") {
		t.Fatalf("the comment is gone:\n%s", out)
	}
	if !strings.HasSuffix(out, addCheckBody) {
		t.Fatal("the body changed")
	}
	doc, err := Parse(out)
	if err != nil || len(Validate(doc)) > 0 {
		t.Fatalf("the result is not valid: %v %v", err, Validate(doc))
	}
	rec, err := RecordFrom(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rec.Checks, []Check{agentEdit}) {
		t.Fatalf("checks = %+v", rec.Checks)
	}
}

func TestAddCheckAfterTheChecksThatAreThere(t *testing.T) {
	existing := "checks:\n  - engine: opa\n    ref: policy/s3.rego\n    mode: warn\n"
	out, added, err := AddCheck(addCheckRecord(existing), agentEdit)
	if err != nil || !added {
		t.Fatalf("AddCheck() = %v, %v", added, err)
	}
	doc, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := RecordFrom(doc)
	if err != nil {
		t.Fatal(err)
	}
	want := []Check{{Engine: "opa", Ref: "policy/s3.rego", Mode: "warn"}, agentEdit}
	if !reflect.DeepEqual(rec.Checks, want) {
		t.Fatalf("checks = %+v, want %+v", rec.Checks, want)
	}
}

func TestAddCheckKeepsTheScopeOfAnUnindentedFile(t *testing.T) {
	in := strings.Replace(addCheckRecord("checks: []\n"), "scope:\n  - org: acme\n", "scope:\n- org: acme\n", 1)
	out, added, err := AddCheck(in, agentEdit)
	if err != nil || !added {
		t.Fatalf("AddCheck() = %v, %v", added, err)
	}
	before, _ := Parse(in)
	after, _ := Parse(out)
	if !reflect.DeepEqual(before.Front["scope"], after.Front["scope"]) {
		t.Fatal("the scope changed")
	}
}

func TestAddCheckTwiceAddsOnce(t *testing.T) {
	first, added, err := AddCheck(addCheckRecord("checks: []\n"), agentEdit)
	if err != nil || !added {
		t.Fatal(added, err)
	}
	second, added, err := AddCheck(first, agentEdit)
	if err != nil || added || second != first {
		t.Fatalf("second AddCheck() = %v, %v, same text %v", added, err, second == first)
	}
}

func TestAddCheckKeepsCRLF(t *testing.T) {
	in := strings.ReplaceAll(addCheckRecord("checks: []\n"), "\n", "\r\n")
	out, added, err := AddCheck(in, agentEdit)
	if err != nil || !added {
		t.Fatalf("AddCheck() = %v, %v", added, err)
	}
	if strings.Count(out, "\r\n") != strings.Count(out, "\n") {
		t.Fatal("a line ending is not CRLF")
	}
	if !strings.HasSuffix(out, strings.ReplaceAll(addCheckBody, "\n", "\r\n")) {
		t.Fatal("the body changed")
	}
}

func TestAddCheckRefuses(t *testing.T) {
	tests := []struct {
		name string
		text string
		add  Check
	}{
		{"mixed line endings", strings.Replace(addCheckRecord("checks: []\n"), "\n", "\r\n", 1), agentEdit},
		{"no frontmatter", "# a heading\n", agentEdit},
		{"no checks key", addCheckRecord(""), agentEdit},
		{"checks is not a list", addCheckRecord("checks: none\n"), agentEdit},
		{"no ref", addCheckRecord("checks: []\n"), Check{Engine: "opa"}},
		{"no engine", addCheckRecord("checks: []\n"), Check{Ref: "a.rego"}},
		{"an engine the schema does not know", addCheckRecord("checks: []\n"), Check{Engine: "nope", Ref: "a.rego"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if out, added, err := AddCheck(test.text, test.add); err == nil || added || out != "" {
				t.Fatalf("AddCheck() = %q, %v, %v, want an error and no text", out, added, err)
			}
		})
	}
}
