// Package mcptools is the MCP tool set of ipso: names, schemas, and registration. The local stdio
// server in this module and the remote server in ipso-server register the same tools over their own
// backends, so a client sees one contract (ADR-0073).
package mcptools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

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
	Repo   string   `json:"repo,omitempty" jsonschema:"the repository as owner/name. Left out, a scope that names a repository still matches"`
	Paths  []string `json:"paths,omitempty" jsonschema:"paths from the repository root that the work touches"`
	Env    string   `json:"env,omitempty" jsonschema:"the environment the work targets"`
	Intent string   `json:"intent,omitempty" jsonschema:"what the work is for. It does not change the answer, because deterministic scope decides what applies"`
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
	State       string   `json:"state" jsonschema:"the brand state: Under verification, Verified, or Needs review"`
	Criticality string   `json:"criticality"`
	Record      string   `json:"record" jsonschema:"where the decision is recorded"`
	Sources     []string `json:"sources"`
	Paths       []string `json:"paths" jsonschema:"the globs of the scope. Empty means the whole repository"`
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
	Ref       string `json:"ref" jsonschema:"the id or slug of the decision"`
	AsOfValid string `json:"as_of_valid,omitempty" jsonschema:"a YYYY-MM-DD date. in_force then answers for that date"`
	AsOfTx    string `json:"as_of_tx,omitempty" jsonschema:"a transaction time. Only a server with a registry can answer it"`
}

// GetOutput is one decision. Body is empty for a sensitive decision.
type GetOutput struct {
	Decision Decision `json:"decision"`
	InForce  bool     `json:"in_force"`
	Body     string   `json:"body,omitempty"`
}

// EvaluateInput holds exactly one of a diff and a plan.
type EvaluateInput struct {
	Diff string `json:"diff,omitempty" jsonschema:"a unified diff against the working tree"`
	Plan string `json:"plan,omitempty" jsonschema:"the JSON of terraform show -json or tofu show -json"`
	Env  string `json:"env,omitempty" jsonschema:"the environment to evaluate for"`
}

// EvaluateOutput is the verdict. NotEvaluated names compiled checks this input cannot reach, so a
// clean verdict is not read as covering them.
type EvaluateOutput struct {
	Blocked      bool     `json:"blocked" jsonschema:"true when a block-mode check has an uncovered violation or a check could not evaluate"`
	Lines        []string `json:"lines"`
	SARIF        string   `json:"sarif" jsonschema:"the SARIF 2.1.0 log"`
	NotEvaluated []string `json:"not_evaluated"`
}

// ProposeInput is a new decision for a person to review. Nothing here can approve it.
type ProposeInput struct {
	Title        string   `json:"title" jsonschema:"a short name for the decision"`
	Statement    string   `json:"statement" jsonschema:"what is decided"`
	Rationale    string   `json:"rationale" jsonschema:"why, and what prompted it"`
	Verification string   `json:"verification,omitempty" jsonschema:"how a check could prove it"`
	Paths        []string `json:"paths,omitempty" jsonschema:"globs the decision would apply to. Left out, the whole repository"`
	Env          []string `json:"env,omitempty" jsonschema:"environments the decision would apply to"`
	SessionRef   string   `json:"session_ref,omitempty" jsonschema:"a reference to the agent session"`
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

// NewServer returns a server with the four tools. Only decisions.propose has a side effect, and
// that effect creates a proposal.
func NewServer(version string, backend Backend) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "ipso", Version: version}, &mcp.ServerOptions{
		Instructions: "Engineering decisions in force for this repository. Read them before editing, and propose a new decision instead of working around one. A proposal needs a person's approval.",
	})
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true}
	notDestructive := false
	mcp.AddTool(server, &mcp.Tool{
		Name:        ToolApplicable,
		Title:       "Applicable decisions",
		Description: "List the engineering decisions in force for a repository, paths, and an environment, with their checks and state.",
		Annotations: readOnly,
	}, handler(backend.Applicable))
	mcp.AddTool(server, &mcp.Tool{
		Name:        ToolGet,
		Title:       "Get a decision",
		Description: "Read one engineering decision by id or slug.",
		Annotations: readOnly,
	}, handler(backend.Get))
	mcp.AddTool(server, &mcp.Tool{
		Name:        ToolEvaluate,
		Title:       "Evaluate checks",
		Description: "Evaluate a unified diff or a Terraform or OpenTofu plan against the compiled checks with local engines. Returns verdicts and SARIF, and changes nothing.",
		Annotations: readOnly,
	}, handler(backend.Evaluate))
	mcp.AddTool(server, &mcp.Tool{
		Name:        ToolPropose,
		Title:       "Propose a decision",
		Description: "Record a proposed engineering decision for a person to review. It is not in force until a person approves it.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: &notDestructive},
	}, handler(backend.Propose))
	return server
}

// handler adapts a backend method. An error becomes a tool error the client can read.
func handler[In, Out any](call func(context.Context, In) (Out, error)) mcp.ToolHandlerFor[In, Out] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		out, err := call(ctx, in)
		return nil, out, err
	}
}
