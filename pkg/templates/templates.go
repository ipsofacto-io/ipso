// Package templates lists the built-in check templates of this ipso version, which a check selects
// with `ref: ipso:<id>`: the Terraform plan templates of the OPA engine and the Semgrep templates. It
// is the entry point for callers outside this module that choose a template, such as the ipso-server
// check drafter, so a ref it accepts is one `ipso compile` builds.
package templates

import (
	"slices"
	"strings"
	"sync"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/opa"
	"github.com/ipsofacto-io/ipso/internal/compiler/semgrep"
)

const (
	engineOPA     = "opa"
	engineSemgrep = "semgrep"
	targetPlan    = "terraform-plan"
)

// Template is one built-in template. ID is provider or language, a slash, and a name, such as
// aws/ebs-encrypted, and Ref is the check ref that selects it. Engine and Target are the values a
// check entry needs: opa with terraform-plan for a plan template, and semgrep with no target for a
// Semgrep template. A plan template lists the Terraform resources it reads, and a Semgrep template
// the languages it scans.
type Template struct {
	ID        string
	Ref       string
	Engine    string
	Target    string
	Title     string
	Resources []string
	Languages []string
}

type index struct {
	list  []Template
	byRef map[string]int
}

var catalog = sync.OnceValue(func() index {
	var list []Template
	for _, entry := range opa.Templates() {
		list = append(list, Template{ID: entry.ID, Engine: engineOPA, Target: targetPlan, Title: entry.Title, Resources: entry.Resources})
	}
	for _, entry := range semgrep.Templates() {
		list = append(list, Template{ID: entry.ID, Engine: engineSemgrep, Title: entry.Title, Languages: entry.Languages})
	}
	slices.SortFunc(list, func(a, b Template) int { return strings.Compare(a.ID, b.ID) })
	byRef := make(map[string]int, len(list))
	for i := range list {
		list[i].Ref = compiler.TemplatePrefix + list[i].ID
		if _, dup := byRef[list[i].Ref]; dup {
			panic("template " + list[i].ID + " is built in for two engines")
		}
		byRef[list[i].Ref] = i
	}
	return index{list: list, byRef: byRef}
})

// List returns every built-in template, sorted by id.
func List() []Template {
	src := catalog().list
	out := make([]Template, len(src))
	for i, entry := range src {
		out[i] = clone(entry)
	}
	return out
}

// Lookup returns the template that ref selects, such as ipso:aws/ebs-encrypted. A ref that is not
// one of this version's templates reports false.
func Lookup(ref string) (Template, bool) {
	c := catalog()
	i, ok := c.byRef[ref]
	if !ok {
		return Template{}, false
	}
	return clone(c.list[i]), true
}

func clone(t Template) Template {
	t.Resources = slices.Clone(t.Resources)
	t.Languages = slices.Clone(t.Languages)
	return t
}
