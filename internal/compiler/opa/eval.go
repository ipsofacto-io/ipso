package opa

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/util"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

const (
	// CodePlanFormat means the plan JSON is not a Terraform or OpenTofu plan.
	CodePlanFormat = "plan-format"
	// CodePlanTooLarge means the plan is larger than MaxPlanBytes.
	CodePlanTooLarge = "plan-too-large"
	// CodeEval means one check failed to evaluate.
	CodeEval = "rego-eval"

	// MaxPlanBytes is the largest plan the evaluator reads.
	MaxPlanBytes = 256 << 20
	// evalTimeout bounds one check. A plan that needs longer is an evaluation error.
	evalTimeout = 10 * time.Second
)

// Plan is a Terraform or OpenTofu plan the evaluator can query.
type Plan struct {
	raw   []byte
	value ast.Value
}

// ReadPlan reads one plan from r.
// The input must be JSON with format_version 1.x and a resource_changes array, and at most MaxPlanBytes.
func ReadPlan(r io.Reader) (Plan, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxPlanBytes+1))
	if err != nil {
		return Plan{}, err
	}
	if len(raw) > MaxPlanBytes {
		return Plan{}, &compiler.Error{Code: CodePlanTooLarge, Err: fmt.Errorf("plan is larger than %d bytes", MaxPlanBytes)}
	}
	var header struct {
		FormatVersion   string `json:"format_version"`
		ResourceChanges []any  `json:"resource_changes"`
	}
	if err := json.Unmarshal(raw, &header); err != nil || header.FormatVersion == "" || header.FormatVersion[0] != '1' || header.ResourceChanges == nil {
		return Plan{}, &compiler.Error{Code: CodePlanFormat, Err: fmt.Errorf("expected a Terraform or OpenTofu plan")}
	}
	value, err := planValue(raw)
	if err != nil {
		return Plan{}, &compiler.Error{Code: CodePlanFormat, Err: err}
	}
	return Plan{raw: raw, value: value}, nil
}

func planValue(raw []byte) (ast.Value, error) {
	var decoded any
	if err := util.Unmarshal(raw, &decoded); err != nil {
		return nil, err
	}
	return ast.InterfaceToValue(decoded)
}

// SHA256 returns the digest of the plan bytes as they were read.
func (p Plan) SHA256() string {
	sum := sha256.Sum256(p.raw)
	return hex.EncodeToString(sum[:])
}

// EvalCheck evaluates one compiled check against the plan.
// now decides which waivers are in force.
func EvalCheck(entry compiler.Entry, artifacts map[string][]byte, plan Plan, now time.Time) compiler.Outcome {
	policy, ok := artifacts["policy.rego"]
	if !ok {
		return compiler.Outcome{Err: &compiler.Error{Code: CodeEval, Err: fmt.Errorf("missing policy.rego")}}
	}
	modules := map[string]*ast.Module{}
	policyMod, err := parseModule("policy.rego", policy)
	if err != nil {
		return compiler.Outcome{Err: err}
	}
	modules["policy.rego"] = policyMod
	if lib, ok := artifacts["terraform.rego"]; ok {
		libMod, err := parseModule(libName, lib)
		if err != nil {
			return compiler.Outcome{Err: err}
		}
		modules[libName] = libMod
	}
	comp := ast.NewCompiler().
		WithStrict(true).
		WithDefaultRegoVersion(ast.RegoV1).
		WithCapabilities(compileCaps())
	comp.Compile(modules)
	if comp.Failed() {
		return compiler.Outcome{Err: &compiler.Error{Code: CodeEval, Err: comp.Errors}}
	}

	query := denyQuery(policyMod)
	ctx, cancel := context.WithTimeout(context.Background(), evalTimeout)
	defer cancel()
	prepared, err := rego.New(
		rego.Compiler(comp),
		rego.ParsedQuery(query),
		rego.StrictBuiltinErrors(true),
	).PrepareForEval(ctx)
	if err != nil {
		return compiler.Outcome{Err: &compiler.Error{Code: CodeEval, Err: err}}
	}
	rs, err := prepared.Eval(ctx, rego.EvalParsedInput(plan.value))
	if err != nil {
		return compiler.Outcome{Err: &compiler.Error{Code: CodeEval, Err: err}}
	}
	violations, err := normalize(rs)
	if err != nil {
		return compiler.Outcome{Err: &compiler.Error{Code: CodeEval, Err: err}}
	}
	return compiler.Cover(entry, compiler.Outcome{Violations: violations}, now)
}

func denyQuery(mod *ast.Module) ast.Body {
	ref := ast.Ref{ast.VarTerm("data")}
	ref = append(ref, mod.Package.Path[1:]...)
	ref = append(ref, ast.StringTerm("deny"))
	return ast.MustParseBody(ref.String())
}

func normalize(rs rego.ResultSet) ([]compiler.Violation, error) {
	if len(rs) == 0 || len(rs[0].Expressions) == 0 || rs[0].Expressions[0].Value == nil {
		return nil, nil
	}
	items, ok := rs[0].Expressions[0].Value.([]any)
	if !ok {
		return nil, fmt.Errorf("deny returned %T", rs[0].Expressions[0].Value)
	}
	violations := make([]compiler.Violation, 0, len(items))
	for _, item := range items {
		violation, err := oneViolation(item)
		if err != nil {
			return nil, err
		}
		violations = append(violations, violation)
	}
	return violations, nil
}

func oneViolation(item any) (compiler.Violation, error) {
	switch value := item.(type) {
	case string:
		if value == "" {
			return compiler.Violation{}, fmt.Errorf("deny returned an empty string")
		}
		return compiler.Violation{Message: value, Identity: []string{value}}, nil
	case map[string]any:
		message, ok := value["msg"].(string)
		if !ok || message == "" {
			return compiler.Violation{}, fmt.Errorf("deny object has no string msg")
		}
		address := ""
		if raw, present := value["address"]; present {
			address, ok = raw.(string)
			if !ok {
				return compiler.Violation{}, fmt.Errorf("deny object address is not a string")
			}
		}
		identity := address
		if identity == "" {
			identity = message
		}
		return compiler.Violation{Message: message, Address: address, Identity: []string{identity}}, nil
	default:
		return compiler.Violation{}, fmt.Errorf("deny returned %T", item)
	}
}
