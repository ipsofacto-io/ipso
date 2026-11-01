// Package edit evaluates a proposed agent edit against compiled checks with the target agent-edit.
// Rego reads the proposal as its input and runs in this process, so the hot path needs no engine
// on PATH and sends nothing anywhere (ADR-0073).
package edit

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/opa"
	"github.com/ipsofacto-io/ipso/internal/edr"
)

// Target is the check target whose Rego reads a Proposal.
const Target = "agent-edit"

// Proposal is the input document of an agent-edit check. Path is slash-separated from the
// repository root. Content is the whole file after the edit. Added is only the new text.
// Command is set for a shell command, which has no path.
type Proposal struct {
	Tool    string `json:"tool"`
	Path    string `json:"path,omitempty"`
	Content string `json:"content,omitempty"`
	Added   string `json:"added,omitempty"`
	Command string `json:"command,omitempty"`
}

// Result is the merged outcome of one check over every proposal it applies to.
type Result struct {
	Entry   compiler.Entry
	Outcome compiler.Outcome
}

// Evaluate runs each in-force agent-edit check on the proposals its scope covers. A proposal with a
// path needs a glob of the check to match it. A proposal with no path reaches every check, because
// a shell command can touch anything. A check that matches no proposal has no result. A non-empty
// env also limits the checks. An error is kept on the result and is never a pass.
func Evaluate(build compiler.Build, proposals []Proposal, env string, now time.Time) ([]Result, error) {
	var results []Result
	for _, entry := range build.Entries {
		if !entry.SelectedFor(Target, env, now) {
			continue
		}
		artifacts, err := build.Artifacts(entry)
		if err != nil {
			return nil, err
		}
		merged := compiler.Outcome{}
		matched := false
		for _, proposal := range proposals {
			if !covers(entry, proposal) {
				continue
			}
			matched = true
			outcome := evalOne(entry, artifacts, proposal, now)
			if outcome.Err != nil {
				merged = outcome
				break
			}
			merged.Violations = append(merged.Violations, outcome.Violations...)
			merged.Waived = merged.Waived || outcome.Waived
		}
		if matched {
			results = append(results, Result{Entry: entry, Outcome: merged})
		}
	}
	return results, nil
}

func covers(entry compiler.Entry, proposal Proposal) bool {
	if proposal.Path == "" || len(entry.Paths) == 0 {
		return true
	}
	for _, glob := range entry.Paths {
		if edr.MatchPath(glob, proposal.Path) {
			return true
		}
	}
	return false
}

func evalOne(entry compiler.Entry, artifacts map[string][]byte, proposal Proposal, now time.Time) compiler.Outcome {
	document, err := json.Marshal(proposal)
	if err != nil {
		return compiler.Outcome{Err: fmt.Errorf("encode the proposal: %w", err)}
	}
	input, err := opa.NewInput(document, document)
	if err != nil {
		return compiler.Outcome{Err: err}
	}
	outcome := opa.EvalCheck(entry, artifacts, input, now)
	for i := range outcome.Violations {
		if proposal.Path == "" {
			continue
		}
		if outcome.Violations[i].Address == "" {
			outcome.Violations[i].Address = proposal.Path
		}
		outcome.Violations[i].Position = &compiler.Position{Path: proposal.Path, StartLine: 1}
	}
	return outcome
}
