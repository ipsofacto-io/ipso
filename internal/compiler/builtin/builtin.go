// Package builtin is the compiler registry linked into the ipso binary.
package builtin

import (
	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/archunit"
	"github.com/ipsofacto-io/ipso/internal/compiler/checkov"
	"github.com/ipsofacto-io/ipso/internal/compiler/cibinding"
	"github.com/ipsofacto-io/ipso/internal/compiler/depcruise"
	"github.com/ipsofacto-io/ipso/internal/compiler/eslint"
	"github.com/ipsofacto-io/ipso/internal/compiler/findings"
	"github.com/ipsofacto-io/ipso/internal/compiler/importlinter"
	"github.com/ipsofacto-io/ipso/internal/compiler/kyverno"
	"github.com/ipsofacto-io/ipso/internal/compiler/llm"
	"github.com/ipsofacto-io/ipso/internal/compiler/opa"
	"github.com/ipsofacto-io/ipso/internal/compiler/semgrep"
)

// Registry returns the compilers linked into the ipso binary.
// Adding an engine means appending its constructor here.
func Registry() compiler.Registry {
	return compiler.NewRegistry(opa.New(), depcruise.New(), semgrep.New(), cibinding.New(), checkov.New(), findings.Snyk(), findings.Wiz(), findings.SonarQube(), findings.Dependabot(), archunit.New(), importlinter.New(), kyverno.New(), eslint.New(), llm.New())
}
