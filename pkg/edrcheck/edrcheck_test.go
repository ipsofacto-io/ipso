package edrcheck

import (
	"slices"
	"testing"
)

const valid = `---
edr: 1
id: 01M6C7Q3Y8R5T2V9W4X6Z0A1B3
slug: tls-on-ingress
title: "Ingress terminates TLS"
status: accepted
owner: team:platform
scope:
  - org: acme
valid_from: 2026-01-01
valid_to: null
review_by: 2027-01-01
supersedes: []
criticality: warning
checks: []
waivers: []
sources:
  - type: pr
    url: https://github.com/acme/platform/pull/1
tags: []
---

# Ingress terminates TLS

## Context

Context.

## Decision

Decision.

## Alternatives considered

- None.

## Consequences

Consequences.

## Verification

Verification.
`

func TestValidate(t *testing.T) {
	if problems := Validate(valid); len(problems) != 0 {
		t.Fatalf("valid record: %v", problems)
	}
	if problems := Validate("not a record"); len(problems) == 0 {
		t.Fatal("a file with no front matter passed")
	}
	if problems := Validate(valid[:len(valid)-40]); len(problems) == 0 {
		t.Fatal("a file with a missing heading passed")
	}
}

func TestParseGlobs(t *testing.T) {
	globs, err := ParseGlobs([]byte("decisions:\n  - adr/**/*.md\n"))
	if err != nil || !slices.Equal(globs, []string{"adr/**/*.md"}) {
		t.Fatalf("globs %v err %v", globs, err)
	}
	if _, err := ParseGlobs([]byte("decisions: []\n")); err == nil {
		t.Fatal("an empty list passed")
	}
	if _, err := ParseGlobs([]byte("decisions: [")); err == nil {
		t.Fatal("malformed YAML passed")
	}
}

func TestIsDecision(t *testing.T) {
	globs := DefaultGlobs()
	if !IsDecision(globs, "docs/decisions/a/b.md") {
		t.Fatal("a nested decision did not match")
	}
	if IsDecision(globs, "docs/other/b.md") || IsDecision(globs, "docs/decisions/b.txt") {
		t.Fatal("a path outside the globs matched")
	}
}
