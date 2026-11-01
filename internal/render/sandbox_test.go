package render

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

// TestSandboxStopsRemoteFetch hands the pinned kustomize remote entries directly, past the walk, and
// needs IPSO_RENDER=1. The job has network access, so a failure here comes from the sandbox.
func TestSandboxStopsRemoteFetch(t *testing.T) {
	if os.Getenv("IPSO_RENDER") == "" {
		t.Skip("IPSO_RENDER is not set")
	}
	if _, err := exec.LookPath("kustomize"); err != nil {
		t.Fatal("kustomize is not on PATH")
	}
	for _, entry := range []string{
		"https://raw.githubusercontent.com/kubernetes/website/main/content/en/examples/pods/simple-pod.yaml",
		"github.com/kubernetes-sigs/kustomize//examples/helloWorld?ref=v3.3.1",
	} {
		t.Run(entry, func(t *testing.T) {
			dir := t.TempDir()
			body := "resources:\n  - " + entry + "\n"
			if err := os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := execTool(context.Background(), "kustomize", []string{"build", dir, "--load-restrictor", "LoadRestrictionsRootOnly"}, t.TempDir())
			var coded *compiler.Error
			if !errors.As(err, &coded) || coded.Code != CodeRun {
				t.Fatalf("err %v, want code %s", err, CodeRun)
			}
		})
	}
}
