// Package opa compiles Rego policies and the built-in Terraform plan templates.
package opa

import (
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/v1/version"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

const (
	// CodeTemplateTarget means an ipso: template check does not target a Terraform plan.
	CodeTemplateTarget = "template-target"
	// CodeRegoParse means the Rego module could not be parsed as Rego v1.
	CodeRegoParse = "rego-parse"
	// CodeRegoCompile means the Rego module failed OPA's compile checks.
	CodeRegoCompile = "rego-compile"
	// CodeRegoImport means the module imports a data package other than its own.
	CodeRegoImport = "rego-import"
	// CodeRegoNoDeny means the module has no multi-value deny rule.
	CodeRegoNoDeny = "rego-no-deny"

	planTarget       = "terraform-plan"
	gatekeeperTarget = "gatekeeper"
	policyName       = "policy.rego"
	libName          = "terraform.rego"
)

// Compiler is the built-in OPA engine.
type Compiler struct{}

// New returns the OPA compiler.
func New() Compiler { return Compiler{} }

// Engine returns the EDR engine value this compiler handles.
func (Compiler) Engine() string { return "opa" }

// Version returns the embedded OPA version.
func (Compiler) Version() string { return version.Version }

// Compile writes policy.rego for one Rego module.
// A ref that starts with ipso: selects a built-in template and also writes terraform.rego.
// target gatekeeper reads one YAML file of a ConstraintTemplate and a Constraint.
// Any other ref is one repository Rego file.
func (Compiler) Compile(in compiler.Input) ([]compiler.Artifact, error) {
	if in.Check.Target == gatekeeperTarget {
		return compileGatekeeper(in)
	}
	if strings.HasPrefix(in.Check.Ref, compiler.TemplatePrefix) {
		return compileTemplate(in)
	}
	return compileRepo(in)
}

func compileTemplate(in compiler.Input) ([]compiler.Artifact, error) {
	if in.Check.Target != planTarget {
		return nil, &compiler.Error{Code: CodeTemplateTarget, Err: fmt.Errorf("target %q", in.Check.Target)}
	}
	id := strings.TrimPrefix(in.Check.Ref, compiler.TemplatePrefix)
	src, ok := lookup(id)
	if !ok {
		return nil, &compiler.Error{Code: compiler.CodeTemplateUnknown, Err: fmt.Errorf("template %q", id)}
	}
	lib := libSource()
	if err := vet(id+".rego", src, true, lib); err != nil {
		return nil, err
	}
	return []compiler.Artifact{
		{Name: policyName, Data: src},
		{Name: libName, Data: lib},
	}, nil
}

func compileRepo(in compiler.Input) ([]compiler.Artifact, error) {
	src, err := compiler.ReadRef(in)
	if err != nil {
		return nil, err
	}
	if err := Vet(in.Check.Ref, src); err != nil {
		return nil, err
	}
	return []compiler.Artifact{{Name: policyName, Data: src}}, nil
}

// Vet checks one repository Rego module the way Compile checks a ref that names no template. It is
// the whole compile step for such a ref, because the artifact is the module itself.
func Vet(name string, src []byte) error {
	return vet(name, src, false, nil)
}
