package importlinter

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/toolrun"
)

const (
	versionTimeout = 30 * time.Second
	checkTimeout   = 10 * time.Minute
	commandWait    = 5 * time.Second
	maxStdoutBytes = 256 << 20
	stderrLimit    = 1024
	probeLimit     = 256

	// grimpVersion is the grimp release import-linter 2.15 is checked with. grimp finds every import,
	// so it decides the verdict as much as import-linter does.
	grimpVersion = "3.18"

	// statusVersion and statusRoot are the exit statuses the shim uses before it runs import-linter.
	statusVersion = 3
	statusRoot    = 4

	probeScript = "import grimp, importlinter; print(importlinter.__version__); print(grimp.__version__)"
)

//go:embed shim.py
var shim string

// Env is one evaluation run: a Python from PATH that carries the pinned engine, and the copied sources.
// Setup creates it and Close removes it. Checks run one at a time, each in its own process.
type Env struct {
	dir  string
	tree *sourceTree
	// timeout, outputLimit, and wait override the production bounds. Zero means the default.
	timeout     time.Duration
	outputLimit int
	wait        time.Duration
}

// Version is the import-linter release the run is pinned to.
func (*Env) Version() string { return version }

// Setup prepares one evaluation run.
// paths are the directories that hold root packages. They are repository-relative, slash-separated,
// and already normalized. Setup checks them, finds python on PATH, and requires the pinned
// import-linter and grimp. The root packages themselves are copied when a check names them.
func Setup(ctx context.Context, root string, paths []string) (*Env, error) {
	named := distinct(paths)
	if err := toolrun.WithinRoot(root, named); err != nil {
		return nil, &compiler.Error{Code: CodePath, Err: err}
	}
	repo, err := os.OpenRoot(root)
	if err != nil {
		return nil, &compiler.Error{Code: CodeRun, Err: err}
	}
	dir, err := os.MkdirTemp("", "ipso-importlinter-")
	if err != nil {
		_ = repo.Close()
		return nil, &compiler.Error{Code: CodeRun, Err: err}
	}
	env := &Env{dir: dir, tree: &sourceTree{repo: repo, named: named, dir: filepath.Join(dir, "src"), staged: map[string]bool{}}}
	if err := env.prepare(ctx); err != nil {
		env.Close()
		return nil, err
	}
	return env, nil
}

func (e *Env) prepare(ctx context.Context) error {
	for _, named := range e.tree.named {
		info, err := e.tree.repo.Stat(named)
		if err != nil {
			return pathError("%s cannot be read", named)
		}
		if !info.IsDir() {
			return pathError("%s is not a directory", named)
		}
	}
	if err := os.Mkdir(e.tree.dir, 0o700); err != nil {
		return &compiler.Error{Code: CodeRun, Err: err}
	}
	return e.checkPython(ctx)
}

// Close removes the temporary directory and closes the repository.
func (e *Env) Close() {
	_ = e.tree.repo.Close()
	_ = os.RemoveAll(e.dir)
}

func distinct(paths []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, path := range paths {
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	return out
}

// checkPython runs the probe once. The command name is a literal, so Go resolves it with LookPath and
// refuses a binary found relative to the current directory. There is no variable, no flag, and no
// lookup inside the repository. It runs in the run's temporary directory, and -I keeps the working
// directory and PYTHON* variables out of the interpreter.
func (e *Env) checkPython(ctx context.Context) error {
	if _, err := exec.LookPath("python"); err != nil {
		return &compiler.Error{Code: CodeMissing, Err: errors.New("python is not on PATH")}
	}
	ctx, cancel := context.WithTimeout(ctx, versionTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python", "-I", "-B", "-X", "utf8", "-c", probeScript)
	cmd.Dir = e.dir
	cmd.Env = childEnv()
	out, err := toolrun.Run(ctx, cmd, toolrun.Limits{Stdout: probeLimit, Stderr: stderrLimit, Wait: commandWait})
	if err != nil {
		return &compiler.Error{Code: CodeMissing, Err: fmt.Errorf("python cannot import import-linter and grimp: %s", toolrun.Excerpt(toolrun.Stderr(err), "python failed"))}
	}
	versions := strings.Fields(string(out.Stdout))
	if len(versions) != 2 {
		return &compiler.Error{Code: CodeVersion, Err: errors.New("the version probe printed an unexpected result")}
	}
	if versions[0] != version || versions[1] != grimpVersion {
		return &compiler.Error{Code: CodeVersion, Err: fmt.Errorf("import-linter %s and grimp %s, ipso runs %s and %s", versions[0], versions[1], version, grimpVersion)}
	}
	return nil
}

// Evaluate runs one compiled check and applies its waivers.
// The check runs the canonical config recovered from the verified artifact, never a file of the repository,
// on a copy of the root packages that python never imports.
func (e *Env) Evaluate(ctx context.Context, entry compiler.Entry, artifacts map[string][]byte, now time.Time) compiler.Outcome {
	if entry.CompilerVersion != version {
		return compiler.Outcome{Err: &compiler.Error{Code: CodeVersion, Err: fmt.Errorf("check compiled for import-linter %s, ipso runs %s", entry.CompilerVersion, version)}}
	}
	config, ok := artifacts[artifactName]
	if !ok {
		return compiler.Outcome{Err: &compiler.Error{Code: compiler.CodeBuildManifest, Err: fmt.Errorf("missing %s", artifactName)}}
	}
	canon, err := ReadCanonical(config)
	if err != nil {
		return compiler.Outcome{Err: err}
	}
	for _, name := range canon.Roots {
		if err := e.tree.stage(ctx, name); err != nil {
			return compiler.Outcome{Err: err}
		}
	}
	stdout, exit, err := e.run(ctx, canon, config)
	if err != nil {
		return compiler.Outcome{Err: err}
	}
	findings, err := ParseOutput(stdout, exit, canon)
	if err != nil {
		return compiler.Outcome{Err: err}
	}
	var violations []compiler.Violation
	for _, item := range findings {
		violations = append(violations, compiler.Violation{Message: item.message(), Identity: item.identity()})
	}
	return compiler.Cover(entry, compiler.Outcome{Violations: violations}, now)
}

// run starts python on the shim. exit is the status of lint_imports: 0 when every contract is kept
// and 1 when one is broken or the engine reported an error. Any other status is an error here.
// The working directory is empty: import-linter puts it first on sys.path.
func (e *Env) run(ctx context.Context, canon Canonical, config []byte) (stdout []byte, exit int, err error) {
	dir, err := os.MkdirTemp(e.dir, "check-")
	if err != nil {
		return nil, 0, &compiler.Error{Code: CodeRun, Err: err}
	}
	defer func() { _ = os.RemoveAll(dir) }()
	work := filepath.Join(dir, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		return nil, 0, &compiler.Error{Code: CodeRun, Err: err}
	}
	configPath := filepath.Join(dir, artifactName)
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		return nil, 0, &compiler.Error{Code: CodeRun, Err: err}
	}
	ctx, cancel := context.WithTimeout(ctx, e.checkLimit())
	defer cancel()

	args := []string{"-I", "-B", "-X", "utf8", "-c", shim, configPath, version, grimpVersion, e.tree.dir}
	args = append(args, canon.Roots...)
	cmd := exec.CommandContext(ctx, "python", args...)
	cmd.Dir = work
	cmd.Env = childEnv()
	out, err := toolrun.Run(ctx, cmd, e.limits())
	if err == nil {
		return out.Stdout, 0, nil
	}
	var exitErr *toolrun.ExitError
	if errors.As(err, &exitErr) {
		var status *exec.ExitError
		if errors.As(exitErr, &status) {
			return e.statusOf(exitErr, status.ExitCode())
		}
	}
	return nil, 0, runErr(err, e.outputMax())
}

func (e *Env) statusOf(exitErr *toolrun.ExitError, code int) ([]byte, int, error) {
	switch code {
	case 1:
		return exitErr.Stdout, 1, nil
	case statusVersion:
		return nil, 0, &compiler.Error{Code: CodeVersion, Err: errors.New("python no longer carries the pinned import-linter and grimp")}
	case statusRoot:
		return nil, 0, &compiler.Error{Code: CodeRun, Err: fmt.Errorf("%s", toolrun.Excerpt(exitErr.Stderr, "a root package has the name of a module the engine uses"))}
	default:
		return nil, 0, &compiler.Error{Code: CodeRun, Err: fmt.Errorf("python exited with status %d: %s", code, toolrun.Excerpt(exitErr.Stderr, "no message"))}
	}
}

func runErr(err error, limit int) error {
	var timeout *toolrun.TimeoutError
	var over *toolrun.OutputError
	switch {
	case errors.As(err, &timeout):
		return &compiler.Error{Code: CodeRun, Err: errors.New("timed out")}
	case errors.As(err, &over):
		return &compiler.Error{Code: CodeOutput, Err: fmt.Errorf("output is larger than %d bytes", limit)}
	default:
		return &compiler.Error{Code: CodeRun, Err: fmt.Errorf("%s", toolrun.Excerpt(toolrun.Stderr(err), "python failed"))}
	}
}

// plainTextVars are the variables Rich reads to pick width, colour, and terminal mode. They are
// replaced, so the report has the same shape on every runner.
var plainTextVars = map[string]struct{}{
	"COLUMNS":                    {},
	"LINES":                      {},
	"JUPYTER_COLUMNS":            {},
	"JUPYTER_LINES":              {},
	"NO_COLOR":                   {},
	"FORCE_COLOR":                {},
	"TTY_COMPATIBLE":             {},
	"TTY_INTERACTIVE":            {},
	"TERM":                       {},
	"COLORTERM":                  {},
	"DATABRICKS_RUNTIME_VERSION": {},
}

// childEnv is the runner environment with the plain-text variables replaced. PYTHON* variables stay,
// and -I makes the interpreter ignore them. Every other variable is inherited, so the step that
// runs ipso should not export secrets.
func childEnv() []string {
	environ := os.Environ()
	out := make([]string, 0, len(environ)+3)
	for _, item := range environ {
		key, _, _ := strings.Cut(item, "=")
		if _, drop := plainTextVars[strings.ToUpper(key)]; drop {
			continue
		}
		out = append(out, item)
	}
	return append(out, "NO_COLOR=1", "TERM=dumb", "COLUMNS=65536")
}

func (e *Env) limits() toolrun.Limits {
	return toolrun.Limits{Stdout: e.outputMax(), Stderr: stderrLimit, Wait: e.waitDelay()}
}

func (e *Env) checkLimit() time.Duration {
	if e.timeout > 0 {
		return e.timeout
	}
	return checkTimeout
}

func (e *Env) waitDelay() time.Duration {
	if e.wait > 0 {
		return e.wait
	}
	return commandWait
}

func (e *Env) outputMax() int {
	if e.outputLimit > 0 {
		return e.outputLimit
	}
	return maxStdoutBytes
}
