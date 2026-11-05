//go:build unix

package importlinter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

// The tests below put a fake python first on PATH. It answers the version probe and, for the shim run,
// records how it was started and prints a captured report. Its ls calls run with a width ls accepts: the
// product sets COLUMNS=65536 for import-linter, and a newer ls writes a warning about that to stderr, which
// would join the error text the tests compare.
const fakePython = `#!/bin/sh
if [ "$#" -eq 6 ]; then
  printf '%s\n%s\n' "$FAKE_LINTER" "$FAKE_GRIMP"
  exit "${FAKE_PROBE_EXIT:-0}"
fi
{
  echo "pwd=$(/bin/pwd -P)"
  echo "entries=[$(COLUMNS=80 /bin/ls -A)]"
  echo "env=$NO_COLOR $TERM $COLUMNS ${FORCE_COLOR-unset} ${LINES-unset} ${COLORTERM-unset}"
  echo "flags=$1 $2 $3 $4 $5"
  echo "config=$7"
  echo "versions=$8 $9"
  echo "src=[$(COLUMNS=80 /bin/ls "${10}")]"
  echo "roots=${11} ${12}"
} > "$FAKE_LOG"
/bin/cp "$7" "$FAKE_CONFIG"
if [ -n "$FAKE_SLEEP" ]; then
  /bin/sleep "$FAKE_SLEEP"
fi
if [ -n "$FAKE_OUT" ]; then
  /bin/cat "$FAKE_OUT"
fi
printf '%s' "$FAKE_ERR" >&2
exit "${FAKE_EXIT:-0}"
`

type fake struct {
	log    string
	config string
}

// useFakePython installs the script and sets the environment it reads. A test changes a value with t.Setenv.
func useFakePython(t *testing.T) fake {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "python"), []byte(fakePython), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":/usr/bin:/bin")
	f := fake{log: filepath.Join(t.TempDir(), "log"), config: filepath.Join(t.TempDir(), "config")}
	t.Setenv("FAKE_LOG", f.log)
	t.Setenv("FAKE_CONFIG", f.config)
	t.Setenv("FAKE_LINTER", version)
	t.Setenv("FAKE_GRIMP", grimpVersion)
	for _, name := range []string{"FAKE_PROBE_EXIT", "FAKE_SLEEP", "FAKE_OUT", "FAKE_ERR", "FAKE_EXIT"} {
		t.Setenv(name, "")
	}
	return f
}

func (f fake) ran() bool {
	_, err := os.Stat(f.log)
	return err == nil
}

func outputPath(t *testing.T, name string) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("testdata", "output", name+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

const everyTypeConfig = `[importlinter]
root_packages =
    shop

[importlinter:contract:forbidden]
name = Forbidden
type = forbidden
source_modules =
    shop.domain
forbidden_modules =
    shop.infra

[importlinter:contract:layers]
name = Layers
type = layers
layers =
    shop.api
    shop.domain

[importlinter:contract:independence]
name = Independence
type = independence
modules =
    shop.billing
    shop.shipping

[importlinter:contract:protected]
name = Protected
type = protected
protected_modules =
    shop.domain
allowed_importers =
    shop.api

[importlinter:contract:siblings]
name = Siblings
type = acyclic_siblings
ancestors =
    shop
`

func fakeRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeTree(t, root, map[string]string{"shop/__init__.py": "", "shop/api/__init__.py": "", "notes.txt": "not copied"})
	return root
}

func fakeEnv(t *testing.T) (*Env, map[string][]byte) {
	t.Helper()
	env, err := Setup(context.Background(), fakeRepo(t), []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(env.Close)
	artifact, err := compileConfig([]byte(everyTypeConfig))
	if err != nil {
		t.Fatal(err)
	}
	return env, map[string][]byte{artifactName: artifact}
}

func evaluate(env *Env, artifacts map[string][]byte) compiler.Outcome {
	return env.Evaluate(context.Background(), entryFor("block"), artifacts, evalNow)
}

func TestSetupProbe(t *testing.T) {
	root := fakeRepo(t)
	ctx := context.Background()

	t.Run("python is not on PATH", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		_, err := Setup(ctx, root, []string{"."})
		requireCode(t, err, CodeMissing)
	})
	t.Run("python cannot import the engine", func(t *testing.T) {
		useFakePython(t)
		t.Setenv("FAKE_PROBE_EXIT", "1")
		_, err := Setup(ctx, root, []string{"."})
		requireCode(t, err, CodeMissing)
	})
	t.Run("another import-linter", func(t *testing.T) {
		useFakePython(t)
		t.Setenv("FAKE_LINTER", "2.14")
		_, err := Setup(ctx, root, []string{"."})
		requireCode(t, err, CodeVersion)
	})
	t.Run("another grimp", func(t *testing.T) {
		useFakePython(t)
		t.Setenv("FAKE_GRIMP", "3.19")
		_, err := Setup(ctx, root, []string{"."})
		requireCode(t, err, CodeVersion)
	})
	t.Run("a probe that prints nothing", func(t *testing.T) {
		useFakePython(t)
		t.Setenv("FAKE_LINTER", "")
		t.Setenv("FAKE_GRIMP", "")
		_, err := Setup(ctx, root, []string{"."})
		requireCode(t, err, CodeVersion)
	})
	t.Run("the pinned engine", func(t *testing.T) {
		useFakePython(t)
		env, err := Setup(ctx, root, []string{".", "."})
		if err != nil {
			t.Fatal(err)
		}
		defer env.Close()
		if env.Version() != version || len(env.tree.named) != 1 {
			t.Fatalf("version %s named %v", env.Version(), env.tree.named)
		}
	})
	t.Run("a failed setup leaves no directory", func(t *testing.T) {
		useFakePython(t)
		before, _ := filepath.Glob(filepath.Join(os.TempDir(), "ipso-importlinter-*"))
		t.Setenv("FAKE_LINTER", "2.14")
		if _, err := Setup(ctx, root, []string{"."}); err == nil {
			t.Fatal("setup passed")
		}
		after, _ := filepath.Glob(filepath.Join(os.TempDir(), "ipso-importlinter-*"))
		if len(after) != len(before) {
			t.Fatalf("temporary directories %v then %v", before, after)
		}
	})
}

func TestEvaluateStartsPythonInIsolation(t *testing.T) {
	f := useFakePython(t)
	env, artifacts := fakeEnv(t)
	t.Setenv("FAKE_OUT", outputPath(t, "violating"))
	t.Setenv("FAKE_EXIT", "1")
	// A runner that exports terminal settings gets the same report as one that does not.
	t.Setenv("FORCE_COLOR", "1")
	t.Setenv("LINES", "10")
	t.Setenv("COLUMNS", "20")
	t.Setenv("COLORTERM", "truecolor")
	t.Setenv("TERM", "xterm-256color")

	out := evaluate(env, artifacts)
	if out.Err != nil || out.Waived || len(out.Violations) != 7 {
		t.Fatalf("outcome %+v", out)
	}
	logged, err := os.ReadFile(f.log)
	if err != nil {
		t.Fatal(err)
	}
	log := string(logged)
	for _, want := range []string{
		"entries=[]",
		"env=1 dumb 65536 unset unset unset",
		"flags=-I -B -X utf8 -c",
		"versions=2.15 3.18",
		"src=[shop]",
		"roots=shop ",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("log misses %q:\n%s", want, log)
		}
	}
	pwd, _, _ := strings.Cut(strings.TrimPrefix(log, "pwd="), "\n")
	if !strings.HasPrefix(log, "pwd=") || filepath.Base(pwd) != "work" {
		t.Fatalf("python did not run in the empty work directory:\n%s", log)
	}
	config, err := os.ReadFile(f.config)
	if err != nil || string(config) != string(artifacts[artifactName]) {
		t.Fatalf("config %q err %v", config, err)
	}
	if got := listing(t, env.dir); strings.Contains(got, "check-") {
		t.Fatalf("a check directory was left behind:\n%s", got)
	}
}

func TestEvaluateKeepsWhatEachExitStatusMeans(t *testing.T) {
	cases := []struct {
		name   string
		out    string
		exit   string
		stderr string
		code   string
		in     string
	}{
		{"engine error", "error-module", "1", "", CodeRun, "does not exist"},
		{"version moved", "", "3", "", CodeVersion, "pinned"},
		{"root name clash", "", "4", "root package os is a module the engine uses", CodeRun, "root package os"},
		{"root name clash without a message", "", "4", "", CodeRun, "a module the engine uses"},
		{"crash", "", "2", "Traceback", CodeRun, "status 2: Traceback"},
		{"killed", "", "137", "", CodeRun, "status 137"},
		{"a report with exit 0 and a broken contract", "violating", "0", "", CodeOutput, "disagree"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useFakePython(t)
			env, artifacts := fakeEnv(t)
			if tc.out != "" {
				t.Setenv("FAKE_OUT", outputPath(t, tc.out))
			}
			t.Setenv("FAKE_EXIT", tc.exit)
			t.Setenv("FAKE_ERR", tc.stderr)
			out := evaluate(env, artifacts)
			requireOutcomeCode(t, out, tc.code)
			if !strings.Contains(out.Err.Error(), tc.in) {
				t.Fatalf("err %v, want %q", out.Err, tc.in)
			}
		})
	}
}

func TestEvaluateErrorIsNeverWaived(t *testing.T) {
	useFakePython(t)
	env, artifacts := fakeEnv(t)
	t.Setenv("FAKE_OUT", outputPath(t, "error-module"))
	t.Setenv("FAKE_EXIT", "1")
	entry := entryFor("block")
	entry.Waivers = []compiler.ManifestWaiver{{Approver: "Ada Lovelace", ValidFrom: "2026-01-01", ValidTo: "2026-03-01"}}
	out := env.Evaluate(context.Background(), entry, artifacts, evalNow)
	if out.Err == nil || out.Waived {
		t.Fatalf("outcome %+v", out)
	}

	t.Setenv("FAKE_OUT", outputPath(t, "violating"))
	out = env.Evaluate(context.Background(), entry, artifacts, evalNow)
	if out.Err != nil || !out.Waived || len(out.Violations) != 7 {
		t.Fatalf("waiver outcome %+v", out)
	}
}

func TestEvaluateStopsAtTheDeadlineAndTheOutputCap(t *testing.T) {
	useFakePython(t)
	env, artifacts := fakeEnv(t)
	t.Setenv("FAKE_OUT", outputPath(t, "violating"))
	t.Setenv("FAKE_EXIT", "1")

	env.outputLimit = 64
	requireOutcomeCode(t, evaluate(env, artifacts), CodeOutput)
	env.outputLimit = 0

	t.Setenv("FAKE_SLEEP", "30")
	env.timeout = 300 * time.Millisecond
	env.wait = 200 * time.Millisecond
	started := time.Now()
	out := evaluate(env, artifacts)
	requireOutcomeCode(t, out, CodeRun)
	if !strings.Contains(out.Err.Error(), "timed out") || time.Since(started) > 10*time.Second {
		t.Fatalf("err %v after %s", out.Err, time.Since(started))
	}
}

func TestEvaluateRefusesBeforeStartingPython(t *testing.T) {
	f := useFakePython(t)
	env, artifacts := fakeEnv(t)
	t.Setenv("FAKE_OUT", outputPath(t, "clean"))

	entry := entryFor("block")
	entry.CompilerVersion = "2.14"
	requireOutcomeCode(t, env.Evaluate(context.Background(), entry, artifacts, evalNow), CodeVersion)

	requireCode(t, env.Evaluate(context.Background(), entryFor("block"), map[string][]byte{}, evalNow).Err, compiler.CodeBuildManifest)

	tampered := map[string][]byte{artifactName: append([]byte("[importlinter]\ncontract_types =\n    x: y.Z\n"), artifacts[artifactName][len("[importlinter]\n"):]...)}
	requireCode(t, evaluate(env, tampered).Err, compiler.CodeBuildManifest)

	other, err := compileConfig([]byte(strings.Replace(everyTypeConfig, "    shop\n\n", "    nowhere\n\n", 1)))
	if err != nil {
		t.Fatal(err)
	}
	requireOutcomeCode(t, evaluate(env, map[string][]byte{artifactName: other}), CodeEmpty)

	if f.ran() {
		t.Fatal("python started for a check that is refused before the run")
	}
}

func TestChildEnvReplacesTheTerminalSettings(t *testing.T) {
	for _, name := range []string{"COLUMNS", "LINES", "JUPYTER_COLUMNS", "NO_COLOR", "FORCE_COLOR", "TTY_COMPATIBLE", "TERM", "COLORTERM", "DATABRICKS_RUNTIME_VERSION"} {
		t.Setenv(name, "x")
	}
	t.Setenv("KEEP_ME", "yes")
	got := map[string]int{}
	for _, item := range childEnv() {
		key, value, _ := strings.Cut(item, "=")
		got[key+"="+value]++
	}
	for _, want := range []string{"NO_COLOR=1", "TERM=dumb", "COLUMNS=65536", "KEEP_ME=yes"} {
		if got[want] != 1 {
			t.Fatalf("%s appears %d times in %v", want, got[want], got)
		}
	}
	for _, gone := range []string{"LINES=x", "FORCE_COLOR=x", "COLORTERM=x", "JUPYTER_COLUMNS=x", "TTY_COMPATIBLE=x", "NO_COLOR=x", "TERM=x", "COLUMNS=x", "DATABRICKS_RUNTIME_VERSION=x"} {
		if got[gone] != 0 {
			t.Fatalf("%s survived", gone)
		}
	}
}
