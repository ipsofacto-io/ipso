package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso/internal/auth"
	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/builtin"
	"github.com/ipsofacto-io/ipso/pkg/llmcheck"
	"github.com/ipsofacto-io/ipso/pkg/mcptools"
)

const firewallEDR = `---
edr: 1
id: 01M87K0A1B2C3D4E5F6G7H8J9K
slug: prod-firewall-deny-default-egress
title: Production firewall policies deny default internet egress
status: verified
owner: team:netsec
scope:
  - org: acme
    env: [prod]
valid_from: 2026-11-01
valid_to: null
review_by: 2027-05-01
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

Unrestricted egress widens blast radius.

## Decision

Production firewall policies MUST deny default 0.0.0.0/0 egress.

## Alternatives considered

- Default allow.

## Consequences

Explicit allowlists required.

## Verification

Evaluated with engine: llm over firewall policy JSON snapshots.
`

const validFirewallLLMSpec = `{
  "version": 1,
  "target": "json-snapshot",
  "rubric": "Production firewall policies must deny default 0.0.0.0/0 egress.",
  "fixtures": [
    {"id": "deny-default", "expect": "allow", "input": "{\"default_egress\":\"deny\"}"},
    {"id": "open-egress", "expect": "deny", "input": "{\"default_egress\":\"0.0.0.0/0 allow\"}"}
  ]
}
`

func TestLLMCheckCompileEvaluateRedactionAndQuoteGate(t *testing.T) {
	now := time.Date(2026, 11, 24, 15, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	t.Chdir(dir)

	var out, errOut bytes.Buffer
	if code := run([]string{"init"}, &out, &errOut, deps{now: func() time.Time { return now }, registry: builtin.Registry()}); code != 0 {
		t.Fatalf("init failed (%d): %s", code, errOut.String())
	}
	if err := os.MkdirAll(filepath.Join(dir, "docs/decisions"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".ipso/checks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docs/decisions/firewall.md"), []byte(firewallEDR), 0o644); err != nil {
		t.Fatal(err)
	}

	// Missing deny fixture must fail ipso compile when mode is block.
	incompleteSpec := `{"version":1,"target":"json-snapshot","rubric":"Deny 0.0.0.0/0 egress.","fixtures":[{"id":"ok","expect":"allow","input":"{\"default_egress\":\"deny\"}"}]}`
	if err := os.WriteFile(filepath.Join(dir, ".ipso/checks/firewall-egress.llm.json"), []byte(incompleteSpec), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"compile"}, &out, &errOut, deps{now: func() time.Time { return now }, registry: builtin.Registry()}); code == 0 || !strings.Contains(out.String()+errOut.String(), llmcheck.CodeFixturesRequired) {
		t.Fatalf("expected %s on compile, got code=%d stdout=%s stderr=%s", llmcheck.CodeFixturesRequired, code, out.String(), errOut.String())
	}

	// Valid allow + deny fixtures compile cleanly and preserve max_age_days=7.
	if err := os.WriteFile(filepath.Join(dir, ".ipso/checks/firewall-egress.llm.json"), []byte(validFirewallLLMSpec), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"compile"}, &out, &errOut, deps{now: func() time.Time { return now }, registry: builtin.Registry()}); code != 0 {
		t.Fatalf("compile failed (%d): %s", code, errOut.String())
	}
	build, err := compiler.LoadBuild(dir)
	if err != nil {
		t.Fatalf("LoadBuild: %v", err)
	}
	if len(build.Entries) != 1 || build.Entries[0].MaxAgeDays != 7 {
		t.Fatalf("entries = %+v, want max_age_days=7", build.Entries)
	}

	snapshotPath := filepath.Join(dir, "snapshot.json")
	rawSnapshot := `{"contact":"ops@acme.io","api_key":"topsecret12345","rule":"egress-all","cidr":"0.0.0.0/0","action":"allow"}`
	if err := os.WriteFile(snapshotPath, []byte(rawSnapshot), 0o600); err != nil {
		t.Fatal(err)
	}

	mode := "grounded-fail"
	var seenInput string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/llm/evaluate":
			var req serverLLMEvalRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			seenInput = req.RedactedInput
			w.Header().Set("Content-Type", "application/json")
			if mode == "ungrounded" {
				_ = json.NewEncoder(w).Encode(serverLLMEvalResponse{
					Verdict:       "fail",
					Findings:      []llmcheck.Finding{{Quote: "paraphrased quote not in input", Message: "Open egress."}},
					ModelID:       "mistral-large-eu-2026",
					PromptVersion: llmcheck.PromptVersion,
				})
				return
			}
			_ = json.NewEncoder(w).Encode(serverLLMEvalResponse{
				Verdict:       "fail",
				Findings:      []llmcheck.Finding{{Quote: `"cidr":"0.0.0.0/0","action":"allow"`, Message: "Default internet egress is enabled."}},
				ModelID:       "mistral-large-eu-2026",
				PromptVersion: llmcheck.PromptVersion,
			})
		case "/v1/decisions/health":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(mcptools.HealthOutput{
				Decisions: []mcptools.DecisionHealth{{
					ID:          "01M87K0A1B2C3D4E5F6G7H8J9K",
					Slug:        "prod-firewall-deny-default-egress",
					Title:       "Production firewall policies deny default internet egress",
					Criticality: "blocking",
					Validity:    mcptools.ValidityHealth{State: "valid", Status: "verified", ReviewBy: "2027-05-01", OpenPremiseReasons: []mcptools.PremiseAlert{}},
					Compliance: mcptools.ComplianceHealth{
						State: "violated",
						Scopes: []mcptools.ScopeCompliance{{
							Env:   "prod",
							State: "violated",
							LatestLive: &mcptools.VerdictSummary{
								SourceKind:    "live",
								Command:       "llm",
								Result:        "fail",
								Violations:    1,
								EvaluatedAt:   "2026-11-24T15:00:00Z",
								MaxAgeDays:    7,
								ModelID:       "mistral-large-eu-2026",
								PromptVersion: llmcheck.PromptVersion,
							},
						}},
					},
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	store := auth.NewMemoryStore()
	_ = store.Save(srv.URL, "ipsocli_abcdefghijklmnopqrstuvwxyz123456")
	d := deps{
		now:        func() time.Time { return now },
		registry:   builtin.Registry(),
		authStore:  store,
		httpClient: srv.Client(),
	}

	reportPath := filepath.Join(dir, "report.json")
	sarifPath := filepath.Join(dir, "results.sarif")
	out.Reset()
	errOut.Reset()
	code := run([]string{"check", "llm", snapshotPath, "--env", "prod", "--live", "--report", reportPath, "--sarif", sarifPath}, &out, &errOut, d)
	if code != 1 {
		t.Fatalf("expected blocking fail exit 1, got %d (stderr=%s)", code, errOut.String())
	}
	if strings.Contains(seenInput, "ops@acme.io") || strings.Contains(seenInput, "topsecret12345") {
		t.Fatalf("local redaction leaked secrets: %s", seenInput)
	}
	if !strings.Contains(out.String(), "[AI-generated]") {
		t.Fatalf("expected AI-generated disclosure in stdout: %s", out.String())
	}
	rawReport, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var parsedReport compiler.LLMReport
	if err := json.Unmarshal(rawReport, &parsedReport); err != nil {
		t.Fatal(err)
	}
	if !parsedReport.Live || len(parsedReport.Verdicts) != 1 || parsedReport.Verdicts[0].Result != "fail" || parsedReport.Verdicts[0].ModelID != "mistral-large-eu-2026" {
		t.Fatalf("report = %+v", parsedReport)
	}

	// Ungrounded quote from server must fail closed as "error".
	mode = "ungrounded"
	out.Reset()
	errOut.Reset()
	code = run([]string{"check", "llm", snapshotPath, "--env", "prod", "--report", reportPath}, &out, &errOut, d)
	if code != 1 {
		t.Fatalf("expected error exit 1 on ungrounded quote, got %d", code)
	}
	rawReport, _ = os.ReadFile(reportPath)
	_ = json.Unmarshal(rawReport, &parsedReport)
	if parsedReport.Verdicts[0].Result != "error" {
		t.Fatalf("verdict = %+v, want error on ungrounded quote", parsedReport.Verdicts[0])
	}

	// ipso status --query firewall prints both validity and compliance with AI-generated label.
	out.Reset()
	errOut.Reset()
	if code := run([]string{"status", "--query", "firewall"}, &out, &errOut, d); code != 0 {
		t.Fatalf("status failed (%d): %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "validity:   valid") || !strings.Contains(out.String(), "compliance: violated") || !strings.Contains(out.String(), "[AI-generated: model=mistral-large-eu-2026") {
		t.Fatalf("unexpected status output:\n%s", out.String())
	}
}

func TestDeliverLLMCheck(t *testing.T) {
	now := time.Date(2026, 11, 24, 15, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	t.Chdir(dir)

	var out, errOut bytes.Buffer
	_ = run([]string{"init"}, &out, &errOut, deps{now: func() time.Time { return now }, registry: builtin.Registry()})
	_ = os.MkdirAll(filepath.Join(dir, "docs/decisions"), 0o755)
	unverified := strings.Replace(firewallEDR, "status: verified", "status: accepted", 1)
	unverified = strings.Replace(unverified, "checks:\n  - engine: llm\n    target: json-snapshot\n    ref: .ipso/checks/firewall-egress.llm.json\n    mode: block\n    max_age_days: 7", "checks: []", 1)
	if err := os.WriteFile(filepath.Join(dir, "docs/decisions/firewall.md"), []byte(unverified), 0o644); err != nil {
		t.Fatal(err)
	}

	specDigest := llmcheck.SHA256Hex([]byte(validFirewallLLMSpec))
	edrID := "01M87K0A1B2C3D4E5F6G7H8J9K"
	payload, _ := json.Marshal(map[string]any{
		"accepted_checks": []map[string]any{{
			"id":               "11111111-2222-3333-4444-555555555555",
			"decision_id":      "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			"edr_id":           edrID,
			"decision_version": 1,
			"version_in_force": 1,
			"engine":           "llm",
			"target":           "json-snapshot",
			"max_age_days":     14,
			"llm_spec":         validFirewallLLMSpec,
			"llm_spec_sha256":  specDigest,
		}},
	})
	out.Reset()
	errOut.Reset()
	code := deliverCmd(dir, []string{"-"}, bytes.NewReader(payload), &out, &errOut, deps{now: func() time.Time { return now }, registry: builtin.Registry()})
	if code != 0 {
		t.Fatalf("deliverCmd failed (%d): %s", code, errOut.String())
	}
	if _, err := os.Stat(filepath.Join(dir, ".ipso/checks/11111111-2222-3333-4444-555555555555.llm.json")); err != nil {
		t.Fatalf("delivered .llm.json missing: %v", err)
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"compile"}, &out, &errOut, deps{now: func() time.Time { return now }, registry: builtin.Registry()}); code != 0 {
		t.Fatalf("compile after deliver failed (%d): %s", code, errOut.String())
	}
}
