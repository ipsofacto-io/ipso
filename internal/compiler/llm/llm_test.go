package llm

import (
	"errors"
	"testing"
	"testing/fstest"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/edr"
	"github.com/ipsofacto-io/ipso/pkg/llmcheck"
)

func TestCompileEnforcesBlockFixtureGate(t *testing.T) {
	repo := fstest.MapFS{
		".ipso/checks/firewall.llm.json": &fstest.MapFile{
			Data: []byte(`{
				"version": 1,
				"target": "json-snapshot",
				"rubric": "Firewall must deny default 0.0.0.0/0 egress.",
				"fixtures": [
					{"id": "ok", "expect": "allow", "input": "{\"egress\":\"deny\"}"}
				]
			}`),
		},
	}
	in := compiler.Input{
		Record: edr.Record{Criticality: "blocking"},
		Check: edr.Check{
			Engine: "llm",
			Target: "json-snapshot",
			Ref:    ".ipso/checks/firewall.llm.json",
		},
		Repo: repo,
	}
	_, err := New().Compile(in)
	var coded *compiler.Error
	if !errors.As(err, &coded) || coded.Code != llmcheck.CodeFixturesRequired {
		t.Fatalf("Compile blocking without deny fixture = %v, want %s", err, llmcheck.CodeFixturesRequired)
	}

	in.Check.Mode = "warn"
	artifacts, err := New().Compile(in)
	if err != nil {
		t.Fatalf("Compile warn mode = %v", err)
	}
	if len(artifacts) != 1 || artifacts[0].Name != llmcheck.ArtifactName {
		t.Fatalf("artifacts = %+v", artifacts)
	}
}
