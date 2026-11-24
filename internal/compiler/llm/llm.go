// Package llm compiles an authoritative engine: llm check file (.llm.json) into
// the canonical check.llm.json artifact and enforces the allow/deny fixture gate
// whenever effective mode is block (ADR-0158).
package llm

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/pkg/llmcheck"
)

const version = "1.0.0"

// Compiler is the built-in engine: llm compiler.
type Compiler struct{}

// New returns the engine: llm compiler.
func New() Compiler { return Compiler{} }

// Engine returns the EDR engine value this compiler handles.
func (Compiler) Engine() string { return "llm" }

// Version returns the compiler contract version stamped into build manifests.
func (Compiler) Version() string { return version }

// Compile reads the .llm.json specification named by ref, enforces target alignment
// and the allow/deny fixture gate when effective mode is block, and emits check.llm.json.
func (Compiler) Compile(in compiler.Input) ([]compiler.Artifact, error) {
	mode, err := in.Check.EffectiveMode(in.Record.Criticality)
	if err != nil {
		return nil, err
	}
	target := in.Check.Target
	if target != "" && !llmcheck.ValidTarget(target) {
		return nil, &compiler.Error{Code: llmcheck.CodeTarget, Err: fmt.Errorf("target %q", target)}
	}
	if !strings.EqualFold(path.Ext(in.Check.Ref), ".json") {
		return nil, &compiler.Error{Code: llmcheck.CodeJSON, Err: fmt.Errorf("ref %q is not a JSON file", in.Check.Ref)}
	}
	src, err := compiler.ReadRef(in)
	if err != nil {
		return nil, err
	}
	spec, err := llmcheck.ParseAndValidate(src, target, mode == "block")
	if err != nil {
		var coded *llmcheck.Error
		if errors.As(err, &coded) {
			return nil, &compiler.Error{Code: coded.Code, Err: coded.Err}
		}
		return nil, &compiler.Error{Code: llmcheck.CodeSchema, Err: err}
	}
	out, err := llmcheck.MarshalCanonical(spec)
	if err != nil {
		return nil, &compiler.Error{Code: llmcheck.CodeJSON, Err: err}
	}
	return []compiler.Artifact{{Name: llmcheck.ArtifactName, Data: out}}, nil
}
