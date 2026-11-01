package render

import (
	"os"
	"strings"
	"testing"
)

func TestPinnedVersions(t *testing.T) {
	raw, err := os.ReadFile("testdata/tool/bin.lock")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, name := range []string{
		"helm-" + HelmVersion + "-linux-amd64 ",
		"helm-" + HelmVersion + "-darwin-arm64 ",
		"kustomize-" + KustomizeVersion + "-linux-amd64 ",
		"kustomize-" + KustomizeVersion + "-darwin-arm64 ",
	} {
		if !strings.Contains(text, name) {
			t.Fatalf("bin.lock does not pin %s", name)
		}
	}
}

func TestParseVersion(t *testing.T) {
	for raw, want := range map[string]string{
		"v4.3.1+gbec5b06\n":     "4.3.1",
		"v5.8.3\n":              "5.8.3",
		"v4.3.1+g1\nsecond\n":   "4.3.1",
		"":                      "",
		"Version: v1.2.3-dirty": "Version: v1.2.3-dirty",
	} {
		if got := parseVersion([]byte(raw)); got != want {
			t.Fatalf("%q: got %q want %q", raw, got, want)
		}
	}
}
