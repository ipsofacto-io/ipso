// Package mcptools is the MCP server of ipso: the tool contract and the protocol. The local stdio
// server in this module and the remote server in ipso-server answer through it over their own
// backends, so a client sees one contract (ADR-0073, ADR-0161, ADR-0163).
package mcptools

import "context"

// Tool names from section 3.5 of the specification and ADR-0161 / ADR-0163.
const (
	ToolApplicable    = "decisions.applicable"
	ToolGet           = "decisions.get"
	ToolHealth        = "decisions.health"
	ToolEvaluate      = "checks.evaluate"
	ToolPropose       = "decisions.propose"
	ToolVerifiability = "decisions.verifiability"
)

// ApplicableInput selects decisions. A field left out widens the answer, so a caller limited to a
// path or an environment must pass it.
type ApplicableInput struct {
	Repo   string   `json:"repo,omitempty"`
	Paths  []string `json:"paths,omitempty"`
	Env    string   `json:"env,omitempty"`
	Intent string   `json:"intent,omitempty"`
}

// Check is one check a decision carries.
type Check struct {
	Engine     string `json:"engine"`
	Target     string `json:"target,omitempty"`
	Mode       string `json:"mode"`
	MaxAgeDays int    `json:"max_age_days,omitempty"`
}

// Decision is one decision in an answer. A sensitive decision has no Title and no Statement.
type Decision struct {
	ID          string   `json:"id"`
	Slug        string   `json:"slug"`
	Title       string   `json:"title,omitempty"`
	Status      string   `json:"status"`
	State       string   `json:"state"`
	Criticality string   `json:"criticality"`
	Record      string   `json:"record"`
	Sources     []string `json:"sources"`
	Paths       []string `json:"paths"`
	Statement   string   `json:"statement,omitempty"`
	Sensitive   bool     `json:"sensitive,omitempty"`
	Checks      []Check  `json:"checks"`
}

// ApplicableOutput lists the decisions in force for the selection.
type ApplicableOutput struct {
	Decisions []Decision `json:"decisions"`
}

// GetInput names one decision and, optionally, the times to read it at.
type GetInput struct {
	Ref       string `json:"ref"`
	AsOfValid string `json:"as_of_valid,omitempty"`
	AsOfTx    string `json:"as_of_tx,omitempty"`
}

// GetOutput is one decision. Body is empty for a sensitive decision.
type GetOutput struct {
	Decision Decision `json:"decision"`
	InForce  bool     `json:"in_force"`
	Body     string   `json:"body,omitempty"`
}

// EvaluateInput holds exactly one of a diff and a plan.
type EvaluateInput struct {
	Diff string `json:"diff,omitempty"`
	Plan string `json:"plan,omitempty"`
	Env  string `json:"env,omitempty"`
}

// EvaluateOutput is the verdict. NotEvaluated names compiled checks this input cannot reach, so a
// clean verdict is not read as covering them.
type EvaluateOutput struct {
	Blocked      bool     `json:"blocked"`
	Lines        []string `json:"lines"`
	SARIF        string   `json:"sarif"`
	NotEvaluated []string `json:"not_evaluated"`
}

// ProposeInput is a new decision for a person to review. Nothing here can approve it.
type ProposeInput struct {
	Title        string   `json:"title"`
	Statement    string   `json:"statement"`
	Rationale    string   `json:"rationale"`
	Verification string   `json:"verification,omitempty"`
	Paths        []string `json:"paths,omitempty"`
	Env          []string `json:"env,omitempty"`
	SessionRef   string   `json:"session_ref,omitempty"`
}

// ProposeOutput says where the proposal is. Its status is always proposed.
type ProposeOutput struct {
	ProposalID string `json:"proposal_id"`
	Status     string `json:"status"`
	Location   string `json:"location"`
}

// HealthInput selects one decision by ref or searches decisions by topic query and scope (ADR-0163).
type HealthInput struct {
	Ref   string `json:"ref,omitempty"`
	Query string `json:"query,omitempty"`
	Repo  string `json:"repo,omitempty"`
	Env   string `json:"env,omitempty"`
}

// PremiseAlert summarizes one open premise reason affecting decision validity.
type PremiseAlert struct {
	PremiseID  string `json:"premise_id"`
	Statement  string `json:"statement,omitempty"`
	ReasonCode string `json:"reason_code"`
	Detail     string `json:"detail,omitempty"`
}

// ValidityHealth reports whether a decision itself is still valid in force (ADR-0163).
type ValidityHealth struct {
	State              string         `json:"state"`
	Status             string         `json:"status"`
	ValidFrom          string         `json:"valid_from,omitempty"`
	ValidTo            string         `json:"valid_to,omitempty"`
	ReviewBy           string         `json:"review_by,omitempty"`
	SupersededBy       string         `json:"superseded_by,omitempty"`
	OpenPremiseReasons []PremiseAlert `json:"open_premise_reasons"`
}

// VerdictSummary reports the most recent change or live verdict for one scope.
type VerdictSummary struct {
	SourceKind    string `json:"source_kind"`
	Command       string `json:"command"`
	Result        string `json:"result"`
	Violations    int    `json:"violations"`
	EvaluatedAt   string `json:"evaluated_at"`
	Stale         bool   `json:"stale"`
	MaxAgeDays    int    `json:"max_age_days"`
	ModelID       string `json:"model_id,omitempty"`
	PromptVersion string `json:"prompt_version,omitempty"`
}

// ScopeCompliance reports compliance health for one repository or environment scope.
type ScopeCompliance struct {
	Repo         string          `json:"repo,omitempty"`
	Env          string          `json:"env,omitempty"`
	State        string          `json:"state"`
	LatestChange *VerdictSummary `json:"latest_change,omitempty"`
	LatestLive   *VerdictSummary `json:"latest_live,omitempty"`
	Waived       bool            `json:"waived,omitempty"`
	Baselined    bool            `json:"baselined,omitempty"`
}

// ComplianceHealth aggregates per-scope compliance and freshness for one decision (ADR-0163).
type ComplianceHealth struct {
	State  string            `json:"state"`
	Note   string            `json:"note,omitempty"`
	Scopes []ScopeCompliance `json:"scopes"`
}

// DecisionHealth pairs separate Validity and Compliance axes for one decision.
type DecisionHealth struct {
	ID          string           `json:"id"`
	Slug        string           `json:"slug"`
	Title       string           `json:"title,omitempty"`
	Criticality string           `json:"criticality"`
	Sensitive   bool             `json:"sensitive,omitempty"`
	Validity    ValidityHealth   `json:"validity"`
	Compliance  ComplianceHealth `json:"compliance"`
}

// HealthOutput lists matching decisions with their separate validity and compliance states.
type HealthOutput struct {
	Decisions []DecisionHealth `json:"decisions"`
}

// VerifiabilityInput carries a draft decision statement for verifiability diagnosis (ADR-0161).
type VerifiabilityInput struct {
	Title     string `json:"title"`
	Statement string `json:"statement"`
	Context   string `json:"context,omitempty"`
	Repo      string `json:"repo,omitempty"`
	Env       string `json:"env,omitempty"`
}

// CandidateCheck is one suggested verification check returned during assisted authoring.
type CandidateCheck struct {
	Engine     string `json:"engine"`
	Target     string `json:"target,omitempty"`
	Ref        string `json:"ref,omitempty"`
	Mode       string `json:"mode,omitempty"`
	MaxAgeDays int    `json:"max_age_days,omitempty"`
	Rego       string `json:"rego,omitempty"`
	LLMSpec    string `json:"llm_spec,omitempty"`
	Rationale  string `json:"rationale,omitempty"`
}

// CandidatePremise is one suggested premise returned during assisted authoring.
type CandidatePremise struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
	Every     int    `json:"every"`
}

// VerifiabilityOutput classifies a draft decision and offers candidate wording, premises, and checks.
type VerifiabilityOutput struct {
	Classification    string             `json:"classification"`
	Summary           string             `json:"summary"`
	Suggestions       []string           `json:"suggestions"`
	CandidateChecks   []CandidateCheck   `json:"candidate_checks"`
	CandidatePremises []CandidatePremise `json:"candidate_premises"`
	AIGenerated       bool               `json:"ai_generated"`
	ModelID           string             `json:"model_id,omitempty"`
	PromptVersion     string             `json:"prompt_version,omitempty"`
}

// Backend answers the tools. The local server reads a checkout, and the remote server reads the registry.
type Backend interface {
	Applicable(context.Context, ApplicableInput) (ApplicableOutput, error)
	Get(context.Context, GetInput) (GetOutput, error)
	Health(context.Context, HealthInput) (HealthOutput, error)
	Evaluate(context.Context, EvaluateInput) (EvaluateOutput, error)
	Propose(context.Context, ProposeInput) (ProposeOutput, error)
	Verifiability(context.Context, VerifiabilityInput) (VerifiabilityOutput, error)
}
