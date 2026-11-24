package mcptools

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ipsofacto-io/ipso/pkg/llmcheck"
)

var (
	hedgeQualifierPattern   = regexp.MustCompile(`(?i)\b(should try|where appropriate|as needed|when possible|if reasonable|reasonable|try to|generally|prefer to|prefer where sensible|best effort|consider using|ideally)\b`)
	humanAttestationPattern = regexp.MustCompile(`(?i)\b(postmortem|retrospective|architecture board|committee|manual sign-off|tabletop exercise|team meeting|on-call rotation)\b`)
	infraKeywordPattern     = regexp.MustCompile(`(?i)(\b(firewall|egress|cidr|security group|terraform|opentofu|tofu|s3|ebs)\b|0\.0\.0\.0/0)`)
	k8sKeywordPattern       = regexp.MustCompile(`(?i)\b(kubernetes|k8s|pod|pods|ingress|networkpolicy|namespace|namespaces)\b`)
	premiseKeywordPattern   = regexp.MustCompile(`(?i)\b(cost|costs|latency|throughput|vendor|vendors)\b`)
)

// AnalyzeVerifiability classifies a draft decision deterministically so local MCP and server
// fallback paths produce identical classifications, candidate checks, and candidate premises.
func AnalyzeVerifiability(in VerifiabilityInput) VerifiabilityOutput {
	combined := in.Title + " " + in.Statement + " " + in.Context
	lower := strings.ToLower(combined)
	if match := hedgeQualifierPattern.FindString(in.Statement); match != "" {
		term := strings.ToLower(match)
		return VerifiabilityOutput{
			Classification: "ambiguous",
			Summary:        fmt.Sprintf("Statement contains non-binding hedge language (%q); replace with an explicit invariant and target scope.", term),
			Suggestions: []string{
				fmt.Sprintf("Remove %q from the statement and state an explicit MUST or MUST NOT invariant with concrete scope.", term),
				"Name any permitted exceptions as explicit scope exclusions or time-bounded waivers.",
			},
			CandidateChecks:   suggestChecksForText(lower, in.Title, in.Statement),
			CandidatePremises: suggestPremisesForText(lower),
			AIGenerated:       false,
		}
	}
	if humanAttestationPattern.MatchString(in.Statement) {
		return VerifiabilityOutput{
			Classification:    "human_attestation_only",
			Summary:           "Decision governs an organizational or human workflow without a machine-readable code or infrastructure artifact; record as accepted without automated checks or attach periodic review.",
			Suggestions:       []string{"Set a review_by date so periodic human review tracks validity, or rewrite around an inspectable repository artifact."},
			CandidateChecks:   []CandidateCheck{},
			CandidatePremises: suggestPremisesForText(lower),
			AIGenerated:       false,
		}
	}
	return VerifiabilityOutput{
		Classification:    "verifiable",
		Summary:           "Statement expresses a concrete technical invariant that can be verified continuously against code changes and live infrastructure snapshots.",
		Suggestions:       []string{},
		CandidateChecks:   suggestChecksForText(lower, in.Title, in.Statement),
		CandidatePremises: suggestPremisesForText(lower),
		AIGenerated:       false,
	}
}

func suggestChecksForText(lower, title, statement string) []CandidateCheck {
	var out []CandidateCheck
	switch {
	case infraKeywordPattern.MatchString(lower):
		out = append(out, CandidateCheck{
			Engine:     "opa",
			Target:     "terraform-plan",
			Mode:       "block",
			MaxAgeDays: 7,
			Rationale:  "Deterministic Rego check over OpenTofu/Terraform plan and refresh-only live state.",
		})
	case k8sKeywordPattern.MatchString(lower):
		out = append(out, CandidateCheck{
			Engine:     "kyverno",
			Target:     "kubernetes-manifest",
			Mode:       "block",
			MaxAgeDays: 7,
			Rationale:  "Kubernetes manifest policy check over CI manifests and live cluster exports.",
		})
	default:
		out = append(out, CandidateCheck{
			Engine:     "semgrep",
			Target:     "diff",
			Mode:       "warn",
			MaxAgeDays: 14,
			Rationale:  "Static analysis check over repository changes.",
		})
	}
	specBytes, err := llmcheck.MarshalCanonical(llmcheck.Spec{
		Version:  llmcheck.SpecVersion,
		Target:   llmcheck.TargetDiff,
		Rubric:   strings.TrimSpace(title + ": " + statement),
		Fixtures: []llmcheck.Fixture{},
	})
	if err == nil {
		out = append(out, CandidateCheck{
			Engine:     "llm",
			Target:     "diff",
			Mode:       "warn",
			MaxAgeDays: 14,
			LLMSpec:    string(specBytes),
			Rationale:  "Grounded LLM check for semantic invariants across diffs; requires approved allow/deny fixtures before mode: block.",
		})
	}
	return out
}

func suggestPremisesForText(lower string) []CandidatePremise {
	if premiseKeywordPattern.MatchString(lower) {
		return []CandidatePremise{{
			ID:        "baseline-assumption",
			Statement: "Re-verify the operational or vendor assumption behind this decision periodically.",
			Every:     90,
		}}
	}
	return []CandidatePremise{}
}
