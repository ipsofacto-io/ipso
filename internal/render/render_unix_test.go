//go:build unix

package render

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

// fakeTool answers the version probe and otherwise records how it was started and prints FAKE_OUT.
// Its paths are written into the script, because the render passes it none of the test's environment.
const fakeTool = `#!/bin/sh
case "$1" in
version)
  printf '%s\n' "@VERSION@"
  exit 0
  ;;
esac
{
  echo "args=$*"
  echo "pwd=$(/bin/pwd -P)"
  /usr/bin/env
} > "@LOG@"
if [ -f "@ERR@" ]; then
  /bin/cat "@ERR@" >&2
fi
if [ -f "@EXIT@" ]; then
  exit 3
fi
/bin/cat "@OUT@"
`

type fake struct {
	log  string
	out  string
	err  string
	exit string
}

func useFake(t *testing.T, name, version, output string) fake {
	t.Helper()
	dir := t.TempDir()
	f := fake{
		log:  filepath.Join(dir, "log"),
		out:  filepath.Join(dir, "out"),
		err:  filepath.Join(dir, "err"),
		exit: filepath.Join(dir, "exit"),
	}
	writeTestFile(t, f.out, output)
	script := strings.NewReplacer("@VERSION@", version, "@LOG@", f.log, "@OUT@", f.out, "@ERR@", f.err, "@EXIT@", f.exit).Replace(fakeTool)
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":/usr/bin:/bin")
	return f
}

func writeTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func chartRepo(t *testing.T) string {
	t.Helper()
	root := resolvedTemp(t)
	writeTestFile(t, filepath.Join(root, "chart/Chart.yaml"), "apiVersion: v2\nname: app\nversion: 0.1.0\n")
	writeTestFile(t, filepath.Join(root, "chart/templates/pod.yaml"), "kind: Pod\n")
	writeTestFile(t, filepath.Join(root, "values.yaml"), "replicas: 1\n")
	return root
}

func kustomizeRepo(t *testing.T) string {
	t.Helper()
	root := resolvedTemp(t)
	writeTestFile(t, filepath.Join(root, "base/kustomization.yaml"), "resources:\n  - pod.yaml\n")
	writeTestFile(t, filepath.Join(root, "base/pod.yaml"), "kind: Pod\n")
	writeTestFile(t, filepath.Join(root, "overlays/prod/kustomization.yaml"), "resources:\n  - ../../base\n")
	return root
}

func resolvedTemp(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var coded *compiler.Error
	if !errors.As(err, &coded) || coded.Code != code {
		t.Fatalf("err %v, want code %s", err, code)
	}
}

const twoDocs = "---\nkind: Pod\n---\nkind: Service\n"

func TestHelmRunsTheSandboxedCommand(t *testing.T) {
	root := chartRepo(t)
	f := useFake(t, "helm", "v4.3.1+gabc123", twoDocs)
	t.Setenv("RUNNER_SECRET", "marker")
	t.Setenv("KUBECONFIG", "/home/me/.kube/config")
	t.Setenv("HELM_PLUGINS", "/home/me/plugins")
	result, err := Helm(context.Background(), root, HelmOptions{
		Chart:       "chart",
		Values:      []string{"values.yaml"},
		Release:     "web",
		Namespace:   "team-a",
		KubeVersion: "1.34.0",
		Out:         "rendered/web",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Path != "rendered/web/manifests.yaml" || result.Documents != 2 {
		t.Fatalf("result %+v", result)
	}
	log, err := os.ReadFile(f.log)
	if err != nil {
		t.Fatal(err)
	}
	text := string(log)
	wantArgs := "args=template web " + filepath.Join(root, "chart") + " --namespace team-a --kube-version 1.34.0 --values " + filepath.Join(root, "values.yaml") + "\n"
	if !strings.Contains(text, wantArgs) {
		t.Fatalf("log %s\nwant %s", text, wantArgs)
	}
	for _, leaked := range []string{"RUNNER_SECRET", "marker", "/home/me"} {
		if strings.Contains(text, leaked) {
			t.Fatalf("%q reached the tool:\n%s", leaked, text)
		}
	}
	for _, want := range []string{"KUBECONFIG=" + os.DevNull, "HTTPS_PROXY=" + closedProxy, "https_proxy=" + closedProxy, "HELM_PLUGINS="} {
		if !strings.Contains(text, want) {
			t.Fatalf("%q missing:\n%s", want, text)
		}
	}
	if strings.Contains(text, "pwd="+root) {
		t.Fatalf("the tool ran in the repository:\n%s", text)
	}
	info, err := os.Stat(filepath.Join(root, "rendered/web/manifests.yaml"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("file %v %v", info, err)
	}
	dirInfo, err := os.Stat(filepath.Join(root, "rendered/web"))
	if err != nil || dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("dir %v %v", dirInfo, err)
	}
	ignore, err := os.ReadFile(filepath.Join(root, "rendered/web/.gitignore"))
	if err != nil || string(ignore) != "*\n" {
		t.Fatalf("ignore %q %v", ignore, err)
	}
}

func TestHelmDefaultsAndUsage(t *testing.T) {
	root := chartRepo(t)
	f := useFake(t, "helm", "v4.3.1", twoDocs)
	if _, err := Helm(context.Background(), root, HelmOptions{Chart: "chart", Out: "out"}); err != nil {
		t.Fatal(err)
	}
	log, err := os.ReadFile(f.log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), "args=template ipso "+filepath.Join(root, "chart")+" --namespace default\n") {
		t.Fatalf("log %s", log)
	}
	for _, opts := range []HelmOptions{
		{Release: "--post-renderer"},
		{Release: strings.Repeat("a", 54)},
		{Namespace: "Team A"},
		{KubeVersion: "--validate"},
	} {
		opts.Chart, opts.Out = "chart", "out"
		_, err := Helm(context.Background(), root, opts)
		wantCode(t, err, CodePath)
	}
}

func TestPinIsEnforced(t *testing.T) {
	root := chartRepo(t)
	useFake(t, "helm", "v4.3.0+gabc", twoDocs)
	_, err := Helm(context.Background(), root, HelmOptions{Chart: "chart", Out: "out"})
	wantCode(t, err, CodeVersion)
	useFake(t, "helm", "not a version", twoDocs)
	_, err = Helm(context.Background(), root, HelmOptions{Chart: "chart", Out: "out"})
	wantCode(t, err, CodeVersion)
	t.Setenv("PATH", t.TempDir())
	_, err = Helm(context.Background(), root, HelmOptions{Chart: "chart", Out: "out"})
	wantCode(t, err, CodeMissing)
}

func TestHelmRefusesBadChartPaths(t *testing.T) {
	useFake(t, "helm", "v4.3.1", twoDocs)
	cases := map[string]func(root string) HelmOptions{
		"missing chart": func(string) HelmOptions { return HelmOptions{Chart: "nope", Out: "out"} },
		"no Chart.yaml": func(root string) HelmOptions {
			writeTestFile(t, filepath.Join(root, "empty/x"), "x")
			return HelmOptions{Chart: "empty", Out: "out"}
		},
		"symlink in chart": func(root string) HelmOptions {
			if err := os.Symlink("/etc/hosts", filepath.Join(root, "chart/templates/hosts.yaml")); err != nil {
				t.Fatal(err)
			}
			return HelmOptions{Chart: "chart", Out: "out"}
		},
		"values symlink": func(root string) HelmOptions {
			if err := os.Symlink("/etc/hosts", filepath.Join(root, "evil.yaml")); err != nil {
				t.Fatal(err)
			}
			return HelmOptions{Chart: "chart", Values: []string{"evil.yaml"}, Out: "out"}
		},
		"missing values": func(string) HelmOptions {
			return HelmOptions{Chart: "chart", Values: []string{"nope.yaml"}, Out: "out"}
		},
		"out inside chart": func(string) HelmOptions { return HelmOptions{Chart: "chart", Out: "chart/rendered"} },
		"out is chart":     func(string) HelmOptions { return HelmOptions{Chart: "chart", Out: "chart"} },
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			root := chartRepo(t)
			_, err := Helm(context.Background(), root, build(root))
			wantCode(t, err, CodePath)
		})
	}
}

func TestOutputDirectoryRules(t *testing.T) {
	useFake(t, "helm", "v4.3.1", twoDocs)
	render := func(root string) error {
		_, err := Helm(context.Background(), root, HelmOptions{Chart: "chart", Out: "rendered/web"})
		return err
	}
	t.Run("a second render replaces the first", func(t *testing.T) {
		root := chartRepo(t)
		if err := render(root); err != nil {
			t.Fatal(err)
		}
		if err := render(root); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("another file is refused", func(t *testing.T) {
		root := chartRepo(t)
		writeTestFile(t, filepath.Join(root, "rendered/web/keep.yaml"), "kind: Pod\n")
		wantCode(t, render(root), CodePath)
		if _, err := os.Stat(filepath.Join(root, "rendered/web/keep.yaml")); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("an existing directory is tightened", func(t *testing.T) {
		root := chartRepo(t)
		if err := os.MkdirAll(filepath.Join(root, "rendered/web"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := render(root); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(root, "rendered/web"))
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("dir %v %v", info, err)
		}
	})
	t.Run("a symlink is refused", func(t *testing.T) {
		root := chartRepo(t)
		outside := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "rendered"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(root, "rendered/web")); err != nil {
			t.Fatal(err)
		}
		wantCode(t, render(root), CodePath)
	})
	t.Run("a symlink inside the repository is refused", func(t *testing.T) {
		root := chartRepo(t)
		if err := os.MkdirAll(filepath.Join(root, "real"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "rendered")); err != nil {
			t.Fatal(err)
		}
		wantCode(t, render(root), CodePath)
	})
	t.Run("a file in the way is refused", func(t *testing.T) {
		root := chartRepo(t)
		writeTestFile(t, filepath.Join(root, "rendered"), "x")
		wantCode(t, render(root), CodePath)
	})
}

func TestFailedRenderLeavesNoManifests(t *testing.T) {
	root := chartRepo(t)
	f := useFake(t, "helm", "v4.3.1", twoDocs)
	opts := HelmOptions{Chart: "chart", Out: "out"}
	if _, err := Helm(context.Background(), root, opts); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(root, "out", ManifestName)
	if _, err := os.Stat(stale); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, f.exit, "x")
	writeTestFile(t, f.err, "Error: template: boom")
	_, err := Helm(context.Background(), root, opts)
	wantCode(t, err, CodeRun)
	if !strings.Contains(err.Error(), "template: boom") {
		t.Fatalf("err %v", err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale manifests survived a failed render: %v", err)
	}
}

func TestOutputIsChecked(t *testing.T) {
	root := chartRepo(t)
	for _, output := range []string{"", "\n", "---\n", "---\n# only a comment\n---\n"} {
		useFake(t, "helm", "v4.3.1", output)
		_, err := Helm(context.Background(), root, HelmOptions{Chart: "chart", Out: "out"})
		wantCode(t, err, CodeEmpty)
	}
	useFake(t, "helm", "v4.3.1", "a: [unclosed\n")
	_, err := Helm(context.Background(), root, HelmOptions{Chart: "chart", Out: "out"})
	wantCode(t, err, CodeOutput)
	if strings.Contains(err.Error(), "unclosed") {
		t.Fatalf("the error quotes rendered output: %v", err)
	}
}

func TestKustomizeRunsTheSandboxedCommand(t *testing.T) {
	root := kustomizeRepo(t)
	f := useFake(t, "kustomize", "v5.8.3", twoDocs)
	t.Setenv("KUSTOMIZE_PLUGIN_HOME", "/home/me/plugins")
	result, err := Kustomize(context.Background(), root, "overlays/prod", "rendered/prod")
	if err != nil {
		t.Fatal(err)
	}
	if result.Documents != 2 {
		t.Fatalf("result %+v", result)
	}
	log, err := os.ReadFile(f.log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), "args=build "+filepath.Join(root, "overlays/prod")+" --load-restrictor LoadRestrictionsRootOnly\n") {
		t.Fatalf("log %s", log)
	}
	if strings.Contains(string(log), "/home/me") {
		t.Fatalf("the plugin home reached the tool:\n%s", log)
	}
}

func TestKustomizeRefusesWhatLeavesTheRepository(t *testing.T) {
	useFake(t, "kustomize", "v5.8.3", twoDocs)
	cases := []struct {
		name  string
		entry string
		code  string
	}{
		{"https resource", "https://example.test/pod.yaml", CodeRemote},
		{"git url", "git@github.com:org/repo.git//base", CodeRemote},
		{"bare github", "github.com/org/repo//base?ref=v1", CodeRemote},
		{"missing", "nope", CodeRemote},
		{"absolute", "/etc", CodeRemote},
		{"parent of the repository", "../../..", CodePath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := kustomizeRepo(t)
			writeTestFile(t, filepath.Join(root, "overlays/prod/kustomization.yaml"), "resources:\n  - "+tc.entry+"\n")
			_, err := Kustomize(context.Background(), root, "overlays/prod", "out")
			wantCode(t, err, tc.code)
		})
	}
	t.Run("a remote generator", func(t *testing.T) {
		root := kustomizeRepo(t)
		writeTestFile(t, filepath.Join(root, "overlays/prod/kustomization.yaml"), "generators:\n  - github.com/org/repo//gen\n")
		_, err := Kustomize(context.Background(), root, "overlays/prod", "out")
		wantCode(t, err, CodeRemote)
	})
	t.Run("an inline transformer is not a path", func(t *testing.T) {
		root := kustomizeRepo(t)
		writeTestFile(t, filepath.Join(root, "overlays/prod/kustomization.yaml"), "transformers:\n  - |-\n    apiVersion: builtin\n    kind: LabelTransformer\n")
		if _, err := Kustomize(context.Background(), root, "overlays/prod", "out"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a remote entry below a local base", func(t *testing.T) {
		root := kustomizeRepo(t)
		writeTestFile(t, filepath.Join(root, "base/kustomization.yaml"), "components:\n  - https://example.test/c\n")
		_, err := Kustomize(context.Background(), root, "overlays/prod", "out")
		wantCode(t, err, CodeRemote)
	})
	t.Run("a base outside the repository through a symlink", func(t *testing.T) {
		root := kustomizeRepo(t)
		outside := t.TempDir()
		writeTestFile(t, filepath.Join(outside, "kustomization.yaml"), "resources: []\n")
		if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(root, "overlays/prod/kustomization.yaml"), "resources:\n  - ../../link\n")
		_, err := Kustomize(context.Background(), root, "overlays/prod", "out")
		wantCode(t, err, CodePath)
	})
	t.Run("a symlink in a walked directory", func(t *testing.T) {
		root := kustomizeRepo(t)
		if err := os.Symlink("/etc/hosts", filepath.Join(root, "base/hosts.yaml")); err != nil {
			t.Fatal(err)
		}
		_, err := Kustomize(context.Background(), root, "overlays/prod", "out")
		wantCode(t, err, CodePath)
	})
	t.Run("no kustomization file", func(t *testing.T) {
		root := kustomizeRepo(t)
		writeTestFile(t, filepath.Join(root, "bare/x"), "x")
		_, err := Kustomize(context.Background(), root, "bare", "out")
		wantCode(t, err, CodePath)
	})
	t.Run("a cycle ends", func(t *testing.T) {
		root := kustomizeRepo(t)
		writeTestFile(t, filepath.Join(root, "base/kustomization.yaml"), "resources:\n  - ../overlays/prod\n")
		if _, err := Kustomize(context.Background(), root, "overlays/prod", "out"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("the other file names work", func(t *testing.T) {
		root := resolvedTemp(t)
		writeTestFile(t, filepath.Join(root, "a/Kustomization"), "resources: []\n")
		if _, err := Kustomize(context.Background(), root, "a", "out"); err != nil {
			t.Fatal(err)
		}
	})
}
