package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler/builtin"
	"github.com/ipsofacto-io/ipso/internal/render"
)

func renderAt(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := run(append([]string{"render"}, args...), &stdout, &stderr, deps{now: time.Now, registry: builtin.Registry()})
	return stdout.String(), stderr.String(), code
}

func TestRenderUsage(t *testing.T) {
	withDir(t, t.TempDir())
	for _, args := range [][]string{
		{},
		{"bogus"},
		{"helm"},
		{"helm", "chart"},
		{"helm", "--out", "out"},
		{"helm", "chart", "--out"},
		{"helm", "chart", "--out", "--values"},
		{"helm", "chart", "--out", "out", "--out", "again"},
		{"helm", "chart", "other", "--out", "out"},
		{"helm", "chart", "--out", "/abs"},
		{"helm", "chart", "--out", "../up"},
		{"helm", "chart", "--out", "."},
		{"helm", ".", "--out", "out"},
		{"helm", "../chart", "--out", "out"},
		{"helm", "chart", "--out", "out", "--values", "../v.yaml"},
		{"helm", "chart", "--out", "out", "--values", "https://example.test/v.yaml"},
		{"helm", "chart", "--out", "out", "--release", "Bad Name"},
		{"helm", "chart", "--out", "out", "--release", "a", "--release", "b"},
		{"helm", "chart", "--out", "out", "--namespace", "Bad"},
		{"helm", "chart", "--out", "out", "--namespace", "a", "--namespace", "b"},
		{"helm", "chart", "--out", "out", "--kube-version", "latest"},
		{"helm", "chart", "--out", "out", "--kube-version", "1.34", "--kube-version", "1.35"},
		{"helm", "chart", "--out", "out", "--post-renderer", "x"},
		{"helm", "chart", "--out", "out", "--set", "a=b"},
		{"kustomize"},
		{"kustomize", "dir"},
		{"kustomize", "dir", "--out", "out", "--values", "v.yaml"},
		{"kustomize", "dir", "--out", "out", "--enable-exec"},
		{"kustomize", "https://example.test/x", "--out", "out"},
	} {
		stdout, stderr, code := renderAt(t, args...)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "usage: ipso render") {
			t.Fatalf("args %q code %d stdout %q stderr %q", args, code, stdout, stderr)
		}
	}
}

func TestRenderIsInHelp(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := run([]string{"help"}, &stdout, &stderr, deps{registry: builtin.Registry()}); code != 0 {
		t.Fatalf("code %d", code)
	}
	for _, want := range []string{"ipso render helm <chart-dir>", "ipso render kustomize <dir>"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("help has no %q:\n%s", want, stdout.String())
		}
	}
}

func TestRenderFailureExitsOne(t *testing.T) {
	root := t.TempDir()
	withDir(t, root)
	stdout, stderr, code := renderAt(t, "helm", "chart", "--out", "out")
	if code != 1 || stdout != "" || !strings.Contains(stderr, render.CodePath) {
		t.Fatalf("code %d stdout %q stderr %q", code, stdout, stderr)
	}
	writeRepoFile(t, root, "k/kustomization.yaml", "resources:\n  - https://example.test/x.yaml\n")
	stdout, stderr, code = renderAt(t, "kustomize", "k", "--out", "out")
	if code != 1 || stdout != "" || !strings.Contains(stderr, render.CodeRemote) {
		t.Fatalf("code %d stdout %q stderr %q", code, stdout, stderr)
	}
}

// The tests below run the pinned tools and the pinned engines. They need IPSO_RENDER=1 with helm 4.3.1,
// kustomize 5.8.3, kyverno 1.19.2, and gator 3.23.1 on PATH, which is how ci / render starts them.
func requireRenderTools(t *testing.T) {
	t.Helper()
	if os.Getenv("IPSO_RENDER") == "" {
		t.Skip("IPSO_RENDER is not set")
	}
	for _, name := range []string{"helm", "kustomize", "kyverno", "gator"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatalf("%s is not on PATH", name)
		}
	}
}

const renderPod = `apiVersion: v1
kind: Pod
metadata:
  name: api
spec:
  securityContext:
    runAsNonRoot: {{ .Values.runAsNonRoot }}
  containers:
    - name: api
      image: registry.example.test/api:1.0.0
`

func writeRenderChart(t *testing.T, root string) {
	t.Helper()
	writeRepoFile(t, root, "chart/Chart.yaml", "apiVersion: v2\nname: api\nversion: 0.1.0\n")
	writeRepoFile(t, root, "chart/values.yaml", "runAsNonRoot: true\n")
	writeRepoFile(t, root, "chart/templates/pod.yaml", renderPod)
	writeRepoFile(t, root, "root-values.yaml", "runAsNonRoot: false\n")
}

func writeRenderKustomize(t *testing.T, root string) {
	t.Helper()
	pod := strings.ReplaceAll(renderPod, "{{ .Values.runAsNonRoot }}", "true")
	writeRepoFile(t, root, "base/kustomization.yaml", "resources:\n  - pod.yaml\n")
	writeRepoFile(t, root, "base/pod.yaml", pod)
	writeRepoFile(t, root, "good/kustomization.yaml", "resources:\n  - ../base\n")
	writeRepoFile(t, root, "bad/kustomization.yaml", `resources:
  - ../base
patches:
  - target:
      kind: Pod
    patch: |
      - op: replace
        path: /spec/securityContext/runAsNonRoot
        value: false
`)
}

func TestRenderHelmThenKyverno(t *testing.T) {
	requireRenderTools(t)
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := kyvernoRepo(t, now, kyvernoCheck, false)
	writeRenderChart(t, root)

	if stdout, stderr, code := renderAt(t, "helm", "chart", "--out", "rendered/good"); code != 0 || !strings.Contains(stdout, "rendered/good/manifests.yaml: 1 document") {
		t.Fatalf("render %d %s %s", code, stdout, stderr)
	}
	if stdout, stderr, code := kyvernoAt(t, now, []string{"rendered/good"}); code != 0 || !strings.Contains(stdout, "pods: checks[0] (block): pass") {
		t.Fatalf("good %d %s %s", code, stdout, stderr)
	}

	if stdout, stderr, code := renderAt(t, "helm", "chart", "--values", "root-values.yaml", "--out", "rendered/bad"); code != 0 {
		t.Fatalf("render %d %s %s", code, stdout, stderr)
	}
	stdout, stderr, code := kyvernoAt(t, now, []string{"rendered/bad"})
	if code != 1 || !strings.Contains(stdout, "pods: checks[0] (block): default/Pod/api: runAsNonRoot must be true") {
		t.Fatalf("bad %d %s %s", code, stdout, stderr)
	}
}

func TestRenderKustomizeThenKyverno(t *testing.T) {
	requireRenderTools(t)
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := kyvernoRepo(t, now, kyvernoCheck, false)
	writeRenderKustomize(t, root)

	if stdout, stderr, code := renderAt(t, "kustomize", "good", "--out", "rendered/good"); code != 0 {
		t.Fatalf("render %d %s %s", code, stdout, stderr)
	}
	if stdout, stderr, code := kyvernoAt(t, now, []string{"rendered/good"}); code != 0 || !strings.Contains(stdout, "pods: checks[0] (block): pass") {
		t.Fatalf("good %d %s %s", code, stdout, stderr)
	}

	if stdout, stderr, code := renderAt(t, "kustomize", "bad", "--out", "rendered/bad"); code != 0 {
		t.Fatalf("render %d %s %s", code, stdout, stderr)
	}
	stdout, stderr, code := kyvernoAt(t, now, []string{"rendered/bad"})
	if code != 1 || !strings.Contains(stdout, "runAsNonRoot must be true") {
		t.Fatalf("bad %d %s %s", code, stdout, stderr)
	}
}

func TestRenderHelmThenGatekeeper(t *testing.T) {
	requireRenderTools(t)
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	root := gatekeeperRepo(t, now, gatekeeperCheck, false)
	writeRepoFile(t, root, "chart/Chart.yaml", "apiVersion: v2\nname: api\nversion: 0.1.0\n")
	writeRepoFile(t, root, "chart/templates/pod.yaml", gatekeeperFixture(t, "gatekeeper-violating/repo/apps/api.yaml.fixture"))
	if stdout, stderr, code := renderAt(t, "helm", "chart", "--out", "rendered/bad"); code != 0 {
		t.Fatalf("render %d %s %s", code, stdout, stderr)
	}
	stdout, stderr, code := gatekeeperAt(t, now, []string{"rendered/bad"})
	if code != 1 || !strings.Contains(stdout, "(block): ") {
		t.Fatalf("bad %d %s %s", code, stdout, stderr)
	}
}

func TestRenderOfflineWithRealTools(t *testing.T) {
	requireRenderTools(t)
	root := t.TempDir()
	withDir(t, root)
	// A remote base stops at the walk, before the tool starts.
	writeRepoFile(t, root, "remote/kustomization.yaml", "resources:\n  - https://raw.githubusercontent.com/kubernetes/website/main/content/en/examples/pods/simple-pod.yaml\n")
	_, stderr, code := renderAt(t, "kustomize", "remote", "--out", "rendered/remote")
	if code != 1 || !strings.Contains(stderr, render.CodeRemote) {
		t.Fatalf("remote code %d stderr %s", code, stderr)
	}
	// The walk does not read generators. The tool refuses one that asks for exec, because no flag enables it.
	writeRepoFile(t, root, "exec/kustomization.yaml", "generators:\n  - gen.yaml\n")
	writeRepoFile(t, root, "exec/gen.yaml", `apiVersion: example.test/v1
kind: Gen
metadata:
  name: gen
  annotations:
    config.kubernetes.io/function: |
      exec:
        path: ./evil.sh
`)
	marker := filepath.Join(root, "ran")
	writeRepoFile(t, root, "exec/evil.sh", "#!/bin/sh\n/usr/bin/touch "+marker+"\n")
	if err := os.Chmod(filepath.Join(root, "exec/evil.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := renderAt(t, "kustomize", "exec", "--out", "rendered/exec"); code != 1 || !strings.Contains(stderr, render.CodeRun) {
		t.Fatalf("exec code %d stderr %s", code, stderr)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("a kustomize exec plugin ran: %v", err)
	}
	// A chart that names a dependency it does not vendor fails, and Helm does not fetch it.
	writeRepoFile(t, root, "dep/Chart.yaml", "apiVersion: v2\nname: dep\nversion: 0.1.0\ndependencies:\n  - name: sub\n    version: 1.0.0\n    repository: https://example.test/charts\n")
	writeRepoFile(t, root, "dep/templates/cm.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n")
	if _, stderr, code := renderAt(t, "helm", "dep", "--out", "rendered/dep"); code != 1 || !strings.Contains(stderr, render.CodeRun) {
		t.Fatalf("dep code %d stderr %s", code, stderr)
	}
	// A template that asks the cluster gets nothing, and no kubeconfig is read.
	writeRepoFile(t, root, "lookup/Chart.yaml", "apiVersion: v2\nname: lookup\nversion: 0.1.0\n")
	writeRepoFile(t, root, "lookup/templates/cm.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\ndata:\n  found: {{ lookup \"v1\" \"Secret\" \"default\" \"s\" | len | quote }}\n")
	t.Setenv("KUBECONFIG", filepath.Join(root, "does-not-exist"))
	if stdout, stderr, code := renderAt(t, "helm", "lookup", "--out", "rendered/lookup"); code != 0 {
		t.Fatalf("lookup %d %s %s", code, stdout, stderr)
	}
	body, err := os.ReadFile(filepath.Join(root, "rendered/lookup", render.ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `found: "0"`) {
		t.Fatalf("lookup rendered %s", body)
	}
}
