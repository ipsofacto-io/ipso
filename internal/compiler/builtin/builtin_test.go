package builtin

import "testing"

func TestRegistry(t *testing.T) {
	for _, engine := range []string{"opa", "depcruise", "semgrep", "ci-binding", "checkov", "snyk", "wiz", "sonarqube", "dependabot", "archunit", "importlinter", "kyverno", "eslint"} {
		got, ok := Registry().Lookup(engine)
		if !ok {
			t.Fatalf("%s compiler is not registered", engine)
		}
		if got.Engine() != engine || got.Version() == "" {
			t.Fatalf("%s compiler %+v", engine, got)
		}
	}
}
