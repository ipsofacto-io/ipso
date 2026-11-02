// Package rulecheck vets one Rego module for the agent-edit target the way `ipso compile` vets a
// repository Rego file, and evaluates it against a proposed edit the way the agent hooks do. It is
// the entry point for callers outside this module that draft checks, such as the ipso-server check
// generator, so a module it accepts is one the OPA engine compiles into a bundle.
package rulecheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/opa"
	"github.com/ipsofacto-io/ipso/internal/edit"
)

// policyName is the artifact name the OPA engine gives a repository module.
const policyName = "policy.rego"

// Edit is the input document of an agent-edit check. Path is slash-separated from the repository
// root. Content is the whole file after the edit, and Added is only the new text. Command is set for
// a shell command, which has no path.
type Edit struct {
	Tool    string
	Path    string
	Content string
	Added   string
	Command string
}

// Rule is one vetted Rego module.
type Rule struct {
	artifacts map[string][]byte
}

// Compile vets src as `ipso compile` vets the Rego file of an opa check: Rego v1, bounded in size
// and depth, no import but its own package and input, OPA's strict compile without network
// builtins, and a multi-value deny rule. A refusal is an error whose Code names the reason.
func Compile(src []byte) (*Rule, error) {
	if err := opa.Vet(policyName, src); err != nil {
		return nil, err
	}
	return &Rule{artifacts: map[string][]byte{policyName: bytes.Clone(src)}}, nil
}

// Deny evaluates the rule against one edit and returns the messages of its denials, none when the
// edit passes. An evaluation that fails, or runs past the engine's time bound, is an error and never
// a pass.
func (r *Rule) Deny(e Edit) ([]string, error) {
	document, err := json.Marshal(edit.Proposal{Tool: e.Tool, Path: e.Path, Content: e.Content, Added: e.Added, Command: e.Command})
	if err != nil {
		return nil, err
	}
	input, err := opa.NewInput(document, document)
	if err != nil {
		return nil, err
	}
	// The entry carries no waiver, so the date does not change the outcome.
	outcome := opa.EvalCheck(compiler.Entry{Engine: "opa", Target: edit.Target}, r.artifacts, input, time.Now())
	if outcome.Err != nil {
		return nil, outcome.Err
	}
	messages := make([]string, 0, len(outcome.Violations))
	for _, violation := range outcome.Violations {
		messages = append(messages, violation.Message)
	}
	return messages, nil
}

// Code returns the stable code of an error from this package, or "". The code names what went
// wrong, so a caller can hand it to a model or a log without the module's text.
func Code(err error) string {
	var coded *compiler.Error
	if errors.As(err, &coded) {
		return coded.Code
	}
	return ""
}
