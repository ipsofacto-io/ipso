package rulecheck_test

import (
	"slices"
	"testing"
	"testing/fstest"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/opa"
	"github.com/ipsofacto-io/ipso/internal/edit"
	"github.com/ipsofacto-io/ipso/internal/edr"
	"github.com/ipsofacto-io/ipso/pkg/rulecheck"
)

const noEnvFiles = `package ipso.checks.no_env_files

deny contains msg if {
	endswith(input.path, ".env")
	msg := "Do not commit .env files."
}

deny contains msg if {
	contains(input.command, "git add .env")
	msg := "Do not stage .env files."
}
`

func TestDenyReadsTheAgentEditInput(t *testing.T) {
	rule, err := rulecheck.Compile([]byte(noEnvFiles))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		edit rulecheck.Edit
		want []string
	}{
		{rulecheck.Edit{Tool: "write", Path: "service/.env", Content: "A=1\n", Added: "A=1\n"}, []string{"Do not commit .env files."}},
		{rulecheck.Edit{Tool: "write", Path: "service/env.go", Content: "package env\n"}, nil},
		{rulecheck.Edit{Tool: "shell", Command: "git add .env"}, []string{"Do not stage .env files."}},
		{rulecheck.Edit{Tool: "shell", Command: "go test ./..."}, nil},
	} {
		got, err := rule.Deny(tc.edit)
		if err != nil {
			t.Fatalf("%+v: %v", tc.edit, err)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%+v: denials %q, want %q", tc.edit, got, tc.want)
		}
	}
}

func TestDenyFailsWhenTheRuleCannotEvaluate(t *testing.T) {
	rule, err := rulecheck.Compile([]byte(`package ipso.checks.bad_number

deny contains msg if {
	to_number(input.path) > 1
	msg := "unreachable"
}
`))
	if err != nil {
		t.Fatal(err)
	}
	if denials, err := rule.Deny(rulecheck.Edit{Tool: "write", Path: "main.go"}); err == nil || rulecheck.Code(err) != opa.CodeEval {
		t.Fatalf("denials %q err %v", denials, err)
	}
}

// TestCompileAgreesWithTheEngine shows that Compile accepts and refuses what the OPA engine of
// `ipso compile` accepts and refuses for an agent-edit check, with the same code.
func TestCompileAgreesWithTheEngine(t *testing.T) {
	for _, tc := range []struct {
		name, src, code string
	}{
		{"valid", noEnvFiles, ""},
		{"rego v0 syntax", "package p\n\ndeny[msg] {\n\tmsg := \"x\"\n}\n", opa.CodeRegoParse},
		{"network builtin", "package p\n\ndeny contains msg if {\n\thttp.send({\"method\": \"get\", \"url\": \"https://example.test\"})\n\tmsg := \"x\"\n}\n", opa.CodeRegoCompile},
		{"foreign import", "package p\n\nimport data.other\n\ndeny contains msg if {\n\tother.x\n\tmsg := \"x\"\n}\n", opa.CodeRegoImport},
		{"no deny", "package p\n\nallow if true\n", opa.CodeRegoNoDeny},
		{"single-value deny", "package p\n\ndeny := \"x\"\n", opa.CodeRegoNoDeny},
	} {
		_, err := rulecheck.Compile([]byte(tc.src))
		if rulecheck.Code(err) != tc.code || (tc.code == "") != (err == nil) {
			t.Errorf("%s: Compile err %v, want code %q", tc.name, err, tc.code)
		}
		_, err = opa.New().Compile(compiler.Input{
			Check: edr.Check{Engine: "opa", Target: edit.Target, Ref: "policies/rule.rego"},
			Repo:  fstest.MapFS{"policies/rule.rego": &fstest.MapFile{Data: []byte(tc.src)}},
		})
		if rulecheck.Code(err) != tc.code || (tc.code == "") != (err == nil) {
			t.Errorf("%s: engine err %v, want code %q", tc.name, err, tc.code)
		}
	}
}
