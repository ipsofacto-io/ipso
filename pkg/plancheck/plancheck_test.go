package plancheck_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso/internal/bundle"
	"github.com/ipsofacto-io/ipso/internal/cli"
	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/opa"
	"github.com/ipsofacto-io/ipso/pkg/plancheck"
)

const planTemplate = `{"format_version":"1.2","resource_changes":[{"address":"aws_ebs_volume.data","mode":"managed","type":"aws_ebs_volume","change":{"actions":["create"],"after":{"encrypted":%t},"after_unknown":{}}}]}`

func plan(encrypted bool) string {
	return fmt.Sprintf(planTemplate, encrypted)
}

func decision(criticality, waivers string) string {
	return fmt.Sprintf(`---
edr: 1
id: 01M6D5D0T0KW7M1P6R2SY8X9ZE
slug: encrypted-volumes
title: "Volumes are encrypted"
status: accepted
owner: team:platform
scope:
  - org: acme
valid_from: 2026-01-01
valid_to: null
review_by: 2030-01-01
supersedes: []
criticality: %s
checks:
  - engine: opa
    target: terraform-plan
    ref: ipso:aws/ebs-encrypted
waivers: %s
sources:
  - type: spec
    url: https://example.test/spec
tags: []
---

# Volumes are encrypted

## Context

Volumes hold data.

## Decision

Volumes are encrypted.

## Alternatives considered

- None.

## Consequences

None.

## Verification

A plan check.
`, criticality, waivers)
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func keys(t *testing.T, dir string) (private, public string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	private = filepath.Join(dir, "private.pem")
	public = filepath.Join(dir, "public.pem")
	write(t, private, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	write(t, public, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})))
	return private, public
}

func runCLI(t *testing.T, args ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := cli.Run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("ipso %v: %d\n%s\n%s", args, code, stdout.String(), stderr.String())
	}
	return strings.TrimSpace(stdout.String())
}

// signedBundle compiles one decision with the CLI, signs it, and removes the checkout's build.
func signedBundle(t *testing.T, record string) (layout, digest, public, private string) {
	t.Helper()
	root := t.TempDir()
	t.Chdir(root)
	write(t, filepath.Join(root, "docs/decisions/volumes.md"), record)
	runCLI(t, "compile")
	layout = filepath.Join(root, "layout")
	private, public = keys(t, t.TempDir())
	digest = runCLI(t, "bundle", "pack", "--layout", layout)
	runCLI(t, "bundle", "sign", "--layout", layout, "--key", private)
	return layout, digest, public, private
}

func load(t *testing.T, record string) *plancheck.Bundle {
	t.Helper()
	layout, digest, public, _ := signedBundle(t, record)
	loaded, err := plancheck.Load(layout, digest, public)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var coded *compiler.Error
	if !errors.As(err, &coded) || coded.Code != code {
		t.Fatalf("err %v, want code %s", err, code)
	}
}

var today = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func TestBlockingViolationBlocks(t *testing.T) {
	report, err := load(t, decision("blocking", "[]")).Evaluate(strings.NewReader(plan(false)), "", today)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Blocked || len(report.Verdicts) != 1 {
		t.Fatalf("report %+v", report)
	}
	verdict := report.Verdicts[0]
	if verdict.Result != plancheck.ResultFail || verdict.Mode != "block" || verdict.Count != 1 || len(verdict.Violations) != 1 {
		t.Fatalf("verdict %+v", verdict)
	}
	if verdict.Violations[0].Address != "aws_ebs_volume.data" || verdict.Slug != "encrypted-volumes" {
		t.Fatalf("verdict %+v", verdict)
	}
	if len(report.PlanSHA256) != 64 || len(report.BundleSHA256) != 64 {
		t.Fatalf("hashes %+v", report)
	}
}

func TestCompliantPlanPasses(t *testing.T) {
	report, err := load(t, decision("blocking", "[]")).Evaluate(strings.NewReader(plan(true)), "", today)
	if err != nil {
		t.Fatal(err)
	}
	if report.Blocked || report.Verdicts[0].Result != plancheck.ResultPass {
		t.Fatalf("report %+v", report)
	}
}

func TestWarningDoesNotBlock(t *testing.T) {
	report, err := load(t, decision("warning", "[]")).Evaluate(strings.NewReader(plan(false)), "", today)
	if err != nil {
		t.Fatal(err)
	}
	if report.Blocked || report.Verdicts[0].Result != plancheck.ResultFail || report.Verdicts[0].Mode != "warn" {
		t.Fatalf("report %+v", report)
	}
}

func TestWaiverCovers(t *testing.T) {
	waiver := "\n  - reason: cutover\n    approver: Ada Lovelace\n    valid_from: 2026-10-01\n    valid_to: 2026-12-01"
	report, err := load(t, decision("blocking", waiver)).Evaluate(strings.NewReader(plan(false)), "", today)
	if err != nil {
		t.Fatal(err)
	}
	verdict := report.Verdicts[0]
	if report.Blocked || verdict.Result != plancheck.ResultWaived || verdict.Count != 1 || len(verdict.Violations) != 0 {
		t.Fatalf("report %+v", report)
	}
}

func TestSameRuleAsTheCLI(t *testing.T) {
	loaded := load(t, decision("blocking", "[]"))
	for _, encrypted := range []bool{true, false} {
		body := plan(encrypted)
		report, err := loaded.Evaluate(strings.NewReader(body), "", today)
		if err != nil {
			t.Fatal(err)
		}
		write(t, "plan.json", body)
		var stdout, stderr bytes.Buffer
		code := cli.Run([]string{"check", "plan", "plan.json"}, &stdout, &stderr)
		if report.Blocked != (code == 1) {
			t.Fatalf("encrypted %t: blocked %t, exit %d\n%s\n%s", encrypted, report.Blocked, code, stdout.String(), stderr.String())
		}
	}
}

func TestNotAPlan(t *testing.T) {
	loaded := load(t, decision("blocking", "[]"))
	_, err := loaded.Evaluate(strings.NewReader(`{"not":"a plan"}`), "", today)
	wantCode(t, err, opa.CodePlanFormat)
	if plancheck.Code(err) != opa.CodePlanFormat || plancheck.Code(errors.New("other")) != "" {
		t.Fatalf("code %q", plancheck.Code(err))
	}
}

func TestLoadRefusesAnythingUnverified(t *testing.T) {
	layout, digest, public, _ := signedBundle(t, decision("blocking", "[]"))
	if _, err := plancheck.Load(layout, "sha256:"+strings.Repeat("0", 64), public); err == nil {
		t.Fatal("another digest loaded")
	}
	_, otherPublic := keys(t, t.TempDir())
	if _, err := plancheck.Load(layout, digest, otherPublic); err == nil {
		t.Fatal("another key loaded")
	}
	_, public2 := keys(t, t.TempDir())
	root := t.TempDir()
	t.Chdir(root)
	write(t, filepath.Join(root, "docs/decisions/volumes.md"), decision("blocking", "[]"))
	runCLI(t, "compile")
	unsigned := filepath.Join(root, "unsigned")
	unsignedDigest := runCLI(t, "bundle", "pack", "--layout", unsigned)
	_, err := plancheck.Load(unsigned, unsignedDigest, public2)
	wantCode(t, err, bundle.CodeUnsigned)
}
