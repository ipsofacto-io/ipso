package findings

import (
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/compilertest"
	"github.com/ipsofacto-io/ipso/internal/edr"
)

func TestCompile(t *testing.T) {
	compilertest.Run(t, Snyk())
}

func TestEngines(t *testing.T) {
	for _, c := range []Compiler{Snyk(), Wiz(), SonarQube(), Dependabot()} {
		if !Known(c.Engine()) || c.Version() != version {
			t.Fatalf("compiler %+v", c)
		}
		in := compiler.Input{Check: edr.Check{Ref: "GHSA-xxxx-xxxx-xxxx", Target: "repo", Job: "ignored"}}
		artifacts, err := c.Compile(in)
		if err != nil || len(artifacts) != 1 || artifacts[0].Name != artifactName {
			t.Fatalf("%s compile %+v %v", c.Engine(), artifacts, err)
		}
		if strings.Contains(string(artifacts[0].Data), "ignored") || strings.Contains(string(artifacts[0].Data), "repo") {
			t.Fatalf("%s kept target or job: %s", c.Engine(), artifacts[0].Data)
		}
		if _, err := c.Compile(compiler.Input{}); compiler.CodeOf(err) != compiler.CodeRefRequired {
			t.Fatalf("%s empty ref %v", c.Engine(), err)
		}
		long := strings.Repeat("a", maxFindingID+1)
		if _, err := c.Compile(compiler.Input{Check: edr.Check{Ref: long}}); compiler.CodeOf(err) != CodeID {
			t.Fatalf("%s long ref %v", c.Engine(), err)
		}
		if _, err := c.Compile(compiler.Input{Check: edr.Check{Ref: " id"}}); compiler.CodeOf(err) != CodeID {
			t.Fatalf("%s spaced ref %v", c.Engine(), err)
		}
	}
}
