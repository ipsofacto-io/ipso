package edr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// publishedSchemaSHA256 is the sha256 of schema/edr-v1.1.schema.json in
// ipsofacto-io/edr-spec (ADR-0159). A published 1.x schema file never changes,
// so the embedded copy must keep this digest.
const publishedSchemaSHA256 = "9ead4e090dbb58ddc985e4109f3485d4c3a5ddb9df6ae2252982aa5d9757e773"

func TestEmbeddedSchemaIsTheEDR11File(t *testing.T) {
	sum := sha256.Sum256(SchemaJSON)
	if got := hex.EncodeToString(sum[:]); got != publishedSchemaSHA256 {
		t.Fatalf("embedded schema sha256 = %s, want the EDR 1.1.0 file %s", got, publishedSchemaSHA256)
	}
}

func TestEmbeddedSchemaIDIsSchemaURL(t *testing.T) {
	var header struct {
		ID string `json:"$id"`
	}
	if err := json.Unmarshal(SchemaJSON, &header); err != nil {
		t.Fatal(err)
	}
	if header.ID != SchemaURL {
		t.Fatalf("$id = %q, want SchemaURL %q", header.ID, SchemaURL)
	}
}

func TestValidateEDR11LLMCheckAndMaxAgeDays(t *testing.T) {
	const raw = `---
edr: 1
id: 01M87K0A1B2C3D4E5F6G7H8J9K
slug: prod-firewall-deny-default-egress
title: Production firewall policies deny default internet egress
status: verified
owner: team:netsec
scope:
  - org: acme
    env: [prod]
valid_from: 2026-11-24
valid_to: null
review_by: 2027-05-24
supersedes: []
criticality: blocking
checks:
  - engine: llm
    target: json-snapshot
    ref: .ipso/checks/firewall-egress.llm.json
    mode: block
    max_age_days: 7
waivers: []
sources:
  - type: pr
    url: https://github.com/acme/network-infra/pull/142
tags: [security, firewall]
---

# Production firewall policies deny default internet egress

## Context

Context.

## Decision

Decision.

## Alternatives considered

- Alternative.

## Consequences

Consequences.

## Verification

Verification.
`
	doc, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if problems := Validate(doc); len(problems) != 0 {
		t.Fatalf("Validate = %v, want none", problems)
	}
	rec, err := RecordFrom(doc)
	if err != nil {
		t.Fatalf("RecordFrom: %v", err)
	}
	if len(rec.Checks) != 1 || rec.Checks[0].Engine != "llm" || rec.Checks[0].MaxAgeDays != 7 {
		t.Fatalf("Checks = %+v, want engine=llm max_age_days=7", rec.Checks)
	}
}
