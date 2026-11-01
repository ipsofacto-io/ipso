// Package mcptools is the MCP server of ipso: the tool contract and the protocol. The local stdio
// server in this module and the remote server in ipso-server answer through it over their own
// backends, so a client sees one contract (ADR-0073).
package mcptools

import "context"

// Tool names from section 3.5 of the specification.
const (
	ToolApplicable = "decisions.applicable"
	ToolGet        = "decisions.get"
	ToolEvaluate   = "checks.evaluate"
	ToolPropose    = "decisions.propose"
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
	Engine string `json:"engine"`
	Target string `json:"target,omitempty"`
	Mode   string `json:"mode"`
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

// Backend answers the tools. The local server reads a checkout, and the remote server reads the registry.
type Backend interface {
	Applicable(context.Context, ApplicableInput) (ApplicableOutput, error)
	Get(context.Context, GetInput) (GetOutput, error)
	Evaluate(context.Context, EvaluateInput) (EvaluateOutput, error)
	Propose(context.Context, ProposeInput) (ProposeOutput, error)
}
