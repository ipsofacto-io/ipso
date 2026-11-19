---
edr: 1
id: 01M5C5QEHHNXJ3D7X2ZCMGXQT7
slug: no-open-lodash-advisory
title: The lodash advisory stays closed
status: accepted
owner: team:security
scope:
  - org: acme
valid_from: 2026-11-01
valid_to: null
review_by: 2027-05-01
supersedes: []
criticality: blocking
checks:
  - engine: snyk
    target: code
    ref: SNYK-JS-LODASH-590103
    job: snyk
    mode: block
waivers: []
sources:
  - type: pr
    url: https://github.com/acme/platform/pull/70
tags: [security]
---

# The lodash advisory stays closed

## Context

A dependency advisory stays open until the lockfile moves past it.

## Decision

SNYK-JS-LODASH-590103 is not an open finding.

## Alternatives considered

- Ignore advisories below a severity.

## Consequences

The check fails while the advisory is open.

## Verification

The evidence file lists open Snyk ids, and this id must be absent from a scan that finished.
