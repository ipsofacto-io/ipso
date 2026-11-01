// Package render turns a Helm chart or a Kustomize directory into one plain manifest file.
// It runs the pinned tool from PATH with no network, no cluster, no plugin, and none of the runner's
// environment. The file it writes is what ipso check kyverno and ipso check gatekeeper read.
package render

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/toolrun"
)

const (
	// CodeMissing means the tool is not on PATH, or its version command failed.
	CodeMissing = "render-missing"
	// CodeVersion means the tool on PATH is not the pinned release.
	CodeVersion = "render-version"
	// CodePath means a named path is missing, holds a symlink, or leaves the repository.
	CodePath = "render-path"
	// CodeRemote means a Kustomize entry is not a file or directory inside the repository.
	CodeRemote = "render-remote"
	// CodeRun means the tool failed or timed out.
	CodeRun = "render-run"
	// CodeOutput means the tool's output is too large or is not YAML.
	CodeOutput = "render-output"
	// CodeEmpty means the tool rendered no document.
	CodeEmpty = "render-empty"

	// HelmVersion is the Helm release ipso renders with.
	HelmVersion = "4.3.1"
	// KustomizeVersion is the Kustomize release ipso renders with.
	KustomizeVersion = "5.8.3"
	// ManifestName is the file a render writes inside the output directory.
	ManifestName = "manifests.yaml"

	ignoreName      = ".gitignore"
	versionTimeout  = 30 * time.Second
	renderTimeout   = 5 * time.Minute
	commandWait     = 5 * time.Second
	maxOutputBytes  = 256 << 20
	stderrLimit     = 1024
	probeLimit      = 4096
	closedProxy     = "http://127.0.0.1:9"
	defaultRelease  = "ipso"
	defaultNS       = "default"
	maxReleaseBytes = 53
	maxNSBytes      = 63
)

var (
	dnsLabel    = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	kubeVersion = regexp.MustCompile(`^v?[0-9]+\.[0-9]+(\.[0-9]+)?$`)
)

// Result is one finished render.
type Result struct {
	// Path is the repository path of the file that was written.
	Path string
	// Documents is how many YAML documents that file holds.
	Documents int
}

// HelmOptions names one chart and how to render it.
// Chart, Values, and Out are repository-relative, slash-separated, and already normalized.
type HelmOptions struct {
	Chart       string
	Values      []string
	Release     string
	Namespace   string
	KubeVersion string
	Out         string
}

// Validate reports whether the names can be passed to Helm. An empty name takes its default.
func (o HelmOptions) Validate() error {
	if o.Release != "" && (len(o.Release) > maxReleaseBytes || !dnsLabel.MatchString(o.Release)) {
		return fmt.Errorf("release %q", o.Release)
	}
	if o.Namespace != "" && (len(o.Namespace) > maxNSBytes || !dnsLabel.MatchString(o.Namespace)) {
		return fmt.Errorf("namespace %q", o.Namespace)
	}
	if o.KubeVersion != "" && !kubeVersion.MatchString(o.KubeVersion) {
		return fmt.Errorf("kube version %q", o.KubeVersion)
	}
	return nil
}

// tool is one pinned binary: its name, how to start it, the arguments that print its version, and the
// release to require. The command name is a literal, so Go resolves it with LookPath and refuses a
// binary found relative to the current directory. No input of a render can name another program.
type tool struct {
	name        string
	command     func(ctx context.Context, args ...string) *exec.Cmd
	versionArgs []string
	pin         string
}

var (
	helmTool = tool{
		name:        "helm",
		command:     func(ctx context.Context, args ...string) *exec.Cmd { return exec.CommandContext(ctx, "helm", args...) },
		versionArgs: []string{"version", "--short"},
		pin:         HelmVersion,
	}
	kustomizeTool = tool{
		name: "kustomize",
		command: func(ctx context.Context, args ...string) *exec.Cmd {
			return exec.CommandContext(ctx, "kustomize", args...)
		},
		versionArgs: []string{"version"},
		pin:         KustomizeVersion,
	}
)

// Helm renders one chart with helm template.
func Helm(ctx context.Context, root string, opts HelmOptions) (Result, error) {
	if err := opts.Validate(); err != nil {
		return Result{}, pathErr("%s", err)
	}
	named := append([]string{opts.Chart}, opts.Values...)
	if err := checkNamed(root, named, opts.Out); err != nil {
		return Result{}, err
	}
	chart := filepath.Join(root, filepath.FromSlash(opts.Chart))
	if err := refuseSymlinks(chart); err != nil {
		return Result{}, err
	}
	if info, err := os.Stat(filepath.Join(chart, "Chart.yaml")); err != nil || !info.Mode().IsRegular() {
		return Result{}, pathErr("%s has no Chart.yaml", opts.Chart)
	}
	args := []string{"template", orDefault(opts.Release, defaultRelease), chart, "--namespace", orDefault(opts.Namespace, defaultNS)}
	if opts.KubeVersion != "" {
		args = append(args, "--kube-version", opts.KubeVersion)
	}
	for _, values := range opts.Values {
		abs := filepath.Join(root, filepath.FromSlash(values))
		info, err := os.Lstat(abs)
		if err != nil || !info.Mode().IsRegular() {
			return Result{}, pathErr("%s is not a regular file", values)
		}
		args = append(args, "--values", abs)
	}
	return renderWith(ctx, root, helmTool, args, opts.Out)
}

// Kustomize renders one directory with kustomize build. Every base and component it names has to be a
// file or directory inside the repository, so nothing reaches the network and nothing outside the repository is read.
func Kustomize(ctx context.Context, root, dir, out string) (Result, error) {
	if err := checkNamed(root, []string{dir}, out); err != nil {
		return Result{}, err
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return Result{}, pathErr("the repository cannot be read")
	}
	target := filepath.Join(resolved, filepath.FromSlash(dir))
	if err := walkKustomization(resolved, target, map[string]struct{}{}); err != nil {
		return Result{}, err
	}
	args := []string{"build", target, "--load-restrictor", "LoadRestrictionsRootOnly"}
	return renderWith(ctx, root, kustomizeTool, args, out)
}

// renderWith prepares the output directory, removes the file of an earlier render so that a failure
// cannot leave stale manifests behind, checks the pin, runs the tool, and writes what it printed.
func renderWith(ctx context.Context, root string, bin tool, args []string, out string) (Result, error) {
	repo, err := os.OpenRoot(root)
	if err != nil {
		return Result{}, runErr("%s", err)
	}
	defer func() { _ = repo.Close() }()
	if err := prepareOut(repo, out); err != nil {
		return Result{}, err
	}
	home, err := os.MkdirTemp("", "ipso-render-")
	if err != nil {
		return Result{}, runErr("%s", err)
	}
	defer func() { _ = os.RemoveAll(home) }()
	if err := probe(ctx, bin, home); err != nil {
		return Result{}, err
	}
	stdout, err := execTool(ctx, bin, args, home)
	if err != nil {
		return Result{}, err
	}
	documents, err := countDocuments(stdout)
	if err != nil {
		return Result{}, err
	}
	if documents == 0 {
		return Result{}, &compiler.Error{Code: CodeEmpty, Err: fmt.Errorf("%s rendered no document", bin.name)}
	}
	if err := writeManifests(repo, out, stdout); err != nil {
		return Result{}, err
	}
	return Result{Path: out + "/" + ManifestName, Documents: documents}, nil
}

// checkNamed refuses a named path that leaves the repository through a symlink, and an output directory
// that is one of the sources or sits inside one, because a later render would read its own output.
func checkNamed(root string, named []string, out string) error {
	all := append(append([]string{}, named...), out)
	if err := toolrun.WithinRoot(root, all); err != nil {
		return &compiler.Error{Code: CodePath, Err: err}
	}
	for _, source := range named {
		if source == "." || out == source || strings.HasPrefix(out+"/", source+"/") {
			return pathErr("%s holds the output directory %s", source, out)
		}
	}
	return nil
}

// prepareOut creates the output directory at mode 0700 with a .gitignore of *, because rendered
// manifests can carry chart values. A symlink, or any other file in the directory, is refused, so a render
// cannot overwrite a tracked file and a later check cannot read a manifest the render did not write.
func prepareOut(repo *os.Root, out string) error {
	current := ""
	for _, segment := range strings.Split(out, "/") {
		current = filepath.Join(current, segment)
		info, err := repo.Lstat(current)
		if errors.Is(err, fs.ErrNotExist) {
			break
		}
		if err != nil {
			return runErr("%s", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return pathErr("%s is a symlink", current)
		}
		if !info.IsDir() {
			return pathErr("%s is not a directory", current)
		}
	}
	if err := repo.MkdirAll(filepath.FromSlash(out), 0o700); err != nil {
		return runErr("%s", err)
	}
	if err := repo.Chmod(filepath.FromSlash(out), 0o700); err != nil {
		return runErr("%s", err)
	}
	dir, err := repo.Open(filepath.FromSlash(out))
	if err != nil {
		return runErr("%s", err)
	}
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil {
		return runErr("%s", err)
	}
	for _, entry := range entries {
		if name := entry.Name(); name != ManifestName && name != ignoreName {
			return pathErr("%s holds %s, which ipso did not write", out, name)
		}
	}
	if err := repo.Remove(filepath.Join(filepath.FromSlash(out), ManifestName)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return runErr("%s", err)
	}
	return nil
}

// writeManifests writes the rendered file at mode 0600 by renaming a temporary file in the same directory.
func writeManifests(repo *os.Root, out string, body []byte) error {
	dir := filepath.FromSlash(out)
	if err := writeFile(repo, filepath.Join(dir, ignoreName), filepath.Join(dir, ".ignore.tmp"), []byte("*\n")); err != nil {
		return runErr("%s", err)
	}
	if err := writeFile(repo, filepath.Join(dir, ManifestName), filepath.Join(dir, ".manifests.tmp"), body); err != nil {
		return runErr("%s", err)
	}
	return nil
}

func writeFile(repo *os.Root, final, temp string, body []byte) error {
	file, err := repo.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(body)
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = repo.Remove(temp)
		return err
	}
	if err := repo.Rename(temp, final); err != nil {
		_ = repo.Remove(temp)
		return err
	}
	return nil
}

// probe runs the tool's version command once.
func probe(ctx context.Context, bin tool, home string) error {
	if _, err := exec.LookPath(bin.name); err != nil {
		return &compiler.Error{Code: CodeMissing, Err: fmt.Errorf("%s is not on PATH", bin.name)}
	}
	ctx, cancel := context.WithTimeout(ctx, versionTimeout)
	defer cancel()
	cmd := bin.command(ctx, bin.versionArgs...)
	cmd.Dir = home
	cmd.Env = sandboxEnv(home)
	out, err := toolrun.Run(ctx, cmd, toolrun.Limits{Stdout: probeLimit, Stderr: stderrLimit, Wait: commandWait})
	if err != nil {
		return &compiler.Error{Code: CodeMissing, Err: fmt.Errorf("%s version: %s", bin.name, toolrun.Excerpt(toolrun.Stderr(err), "no message"))}
	}
	found := parseVersion(out.Stdout)
	if _, _, _, ok := toolrun.ParseSemver(found); !ok {
		return &compiler.Error{Code: CodeVersion, Err: fmt.Errorf("the %s version output is not the shape ipso reads", bin.name)}
	}
	if found != bin.pin {
		return &compiler.Error{Code: CodeVersion, Err: fmt.Errorf("%s %s, ipso renders with %s", bin.name, found, bin.pin)}
	}
	return nil
}

// parseVersion reads "v4.3.1+gbec5b06" and "v5.8.3" to the MAJOR.MINOR.PATCH they name.
func parseVersion(raw []byte) string {
	first, _, _ := strings.Cut(string(raw), "\n")
	found, _, _ := strings.Cut(strings.TrimSpace(first), "+")
	return strings.TrimPrefix(found, "v")
}

func execTool(ctx context.Context, bin tool, args []string, home string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, renderTimeout)
	defer cancel()
	cmd := bin.command(ctx, args...)
	cmd.Dir = home
	cmd.Env = sandboxEnv(home)
	out, err := toolrun.Run(ctx, cmd, toolrun.Limits{Stdout: maxOutputBytes, Stderr: stderrLimit, Wait: commandWait})
	if err == nil {
		return out.Stdout, nil
	}
	var timeout *toolrun.TimeoutError
	var over *toolrun.OutputError
	switch {
	case errors.As(err, &timeout):
		return nil, runErr("%s timed out", bin.name)
	case errors.As(err, &over):
		return nil, &compiler.Error{Code: CodeOutput, Err: fmt.Errorf("%s printed more than %d bytes", bin.name, maxOutputBytes)}
	default:
		return nil, runErr("%s failed: %s", bin.name, toolrun.Excerpt(toolrun.Stderr(err), "no message"))
	}
}

// sandboxEnv is the whole environment of the tool. Nothing is inherited, so no secret, kubeconfig,
// plugin directory, or registry login of the runner reaches it. PATH is empty, which leaves Kustomize no
// git to fetch a remote base with, and the proxy variables point at a closed port, which stops any
// HTTP request a chart or a kustomization could still cause.
func sandboxEnv(home string) []string {
	env := []string{
		"PATH=",
		"HOME=" + home,
		"TMPDIR=" + home,
		"KUBECONFIG=" + os.DevNull,
		"HELM_CACHE_HOME=" + filepath.Join(home, "helm-cache"),
		"HELM_CONFIG_HOME=" + filepath.Join(home, "helm-config"),
		"HELM_DATA_HOME=" + filepath.Join(home, "helm-data"),
		"HELM_PLUGINS=" + filepath.Join(home, "helm-plugins"),
		"NO_PROXY=",
		"no_proxy=",
	}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		env = append(env, key+"="+closedProxy)
	}
	return env
}

// countDocuments counts the YAML documents that hold anything. A file that does not parse is an error
// here, because the engines that read it next would disagree about what it holds.
func countDocuments(raw []byte) (int, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	count := 0
	for {
		var doc yaml.Node
		err := decoder.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return count, nil
		}
		if err != nil {
			return 0, &compiler.Error{Code: CodeOutput, Err: errors.New("the rendered output is not YAML")}
		}
		if len(doc.Content) == 1 && doc.Content[0].Tag != "!!null" {
			count++
		}
	}
}

// refuseSymlinks fails on a symlink anywhere below dir. A tool would follow it out of the tree that was named.
func refuseSymlinks(dir string) error {
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink", entry.Name())
		}
		return nil
	})
	if err != nil {
		return pathErr("%s", err)
	}
	return nil
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func pathErr(format string, args ...any) error {
	return &compiler.Error{Code: CodePath, Err: fmt.Errorf(format, args...)}
}

func runErr(format string, args ...any) error {
	return &compiler.Error{Code: CodeRun, Err: fmt.Errorf(format, args...)}
}
