package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"slices"

	"github.com/ipsofacto-io/ipso/internal/baseline"
	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/sarif"
)

const baselineUsage = "usage: ipso baseline create|update <subcommand> <args>\nsubcommands: plan, checkov, depcruise, semgrep, archunit, importlinter, kyverno, gatekeeper, eslint\nargs are those of ipso check. --env and --input name the input, and a check holds one baseline per input."

// capturedChecks receives the raw outcomes of one evaluation.
type capturedChecks struct {
	done   bool
	scope  baseline.Scope
	checks []sarif.Check
}

type checkRunner func(root string, args []string, stdout, stderr io.Writer, d deps) int

// baselineRunners lists the check commands a baseline can read. ipso check ci is absent, because a job
// that did not succeed means a control did not run, and a baseline would switch that control off.
var baselineRunners = map[string]checkRunner{
	"plan":         planCmd,
	"checkov":      checkovCmd,
	"depcruise":    depcruiseCmd,
	"semgrep":      semgrepCmd,
	"archunit":     archunitCmd,
	"importlinter": importlinterCmd,
	"kyverno":      kyvernoCmd,
	"gatekeeper":   gatekeeperCmd,
	"eslint":       eslintCmd,
}

// baselineCmd runs one check command and records or trims fingerprints. create adds entries only for
// checks with no entry. update only removes fingerprints that no longer occur. Nothing is written when
// any check fails to evaluate.
func baselineCmd(root string, args []string, stdout, stderr io.Writer, d deps) int {
	if len(args) < 2 || (args[0] != "create" && args[0] != "update") {
		fprintln(stderr, baselineUsage)
		return 2
	}
	runner, ok := baselineRunners[args[1]]
	if !ok {
		fprintln(stderr, baselineUsage)
		return 2
	}
	for _, arg := range args[2:] {
		if slices.Contains([]string{"--report", "--sarif", "--bundle", "--digest", "--key"}, arg) {
			fprintln(stderr, baselineUsage)
			return 2
		}
	}
	file, found, err := baseline.Read(root)
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	if !found {
		if args[0] == "update" {
			fprintf(stderr, "%s does not exist, run ipso baseline create\n", baseline.RelPath)
			return 1
		}
		if file, err = baseline.New(); err != nil {
			fprintln(stderr, err)
			return 1
		}
	}
	captured := &capturedChecks{}
	d.capture = captured
	code := runner(root, args[2:], io.Discard, stderr, d)
	if code == 2 {
		fprintln(stderr, baselineUsage)
		return 2
	}
	if !captured.done {
		return code
	}
	failed := false
	for _, check := range captured.checks {
		if check.Outcome.Err != nil {
			fprintf(stderr, "%s: checks[%d] (%s): error: %s\n", check.Entry.Slug, check.Entry.CheckIndex, check.Entry.Mode, check.Outcome.Err)
			failed = true
		}
	}
	if failed {
		fprintln(stderr, "nothing written: a check did not evaluate")
		return 1
	}
	if len(captured.checks) == 0 {
		fprintln(stdout, "no checks selected")
		return 0
	}
	var changed bool
	if args[0] == "create" {
		changed, err = createEntries(&file, captured.scope, captured.checks, stdout)
	} else {
		changed, err = updateEntries(&file, captured.scope, captured.checks, stdout)
	}
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	if !changed {
		fprintf(stdout, "%s unchanged\n", baseline.RelPath)
		return 0
	}
	raw, err := file.Marshal()
	if err != nil {
		fprintln(stderr, err)
		return 1
	}
	if err := writeReport(filepath.Join(root, filepath.FromSlash(baseline.RelPath)), raw); err != nil {
		fprintln(stderr, err)
		return 1
	}
	fprintf(stdout, "wrote %s, run ipso compile to apply it\n", baseline.RelPath)
	return 0
}

func createEntries(file *baseline.File, scope baseline.Scope, checks []sarif.Check, stdout io.Writer) (bool, error) {
	changed := false
	for _, check := range checks {
		entry := check.Entry
		if file.Find(entry.DecisionID, entry.CheckIndex, scope) >= 0 {
			fprintf(stdout, "%s: checks[%d]: already has a baseline for this env and input, name another with --env or --input\n", entry.Slug, entry.CheckIndex)
			continue
		}
		digests, err := baseline.Fingerprints(file.Salt, entry, scope, check.Outcome.Violations)
		if err != nil {
			return false, err
		}
		recorded := []string{}
		skipped := 0
		for _, digest := range digests {
			if digest == "" {
				skipped++
				continue
			}
			recorded = append(recorded, digest)
		}
		file.Checks = append(file.Checks, baseline.Check{DecisionID: entry.DecisionID, CheckIndex: entry.CheckIndex, Env: scope.Env, Input: scope.Input, Fingerprints: recorded})
		changed = true
		line := fmt.Sprintf("%s: checks[%d]: recorded %d", entry.Slug, entry.CheckIndex, len(recorded))
		if skipped > 0 {
			line += fmt.Sprintf(", skipped %d that cannot be baselined", skipped)
		}
		fprintln(stdout, line)
	}
	return changed, nil
}

func updateEntries(file *baseline.File, scope baseline.Scope, checks []sarif.Check, stdout io.Writer) (bool, error) {
	changed := false
	for _, check := range checks {
		entry := check.Entry
		index := file.Find(entry.DecisionID, entry.CheckIndex, scope)
		if index < 0 {
			fprintf(stdout, "%s: checks[%d]: no baseline for this env and input\n", entry.Slug, entry.CheckIndex)
			continue
		}
		digests, err := baseline.Fingerprints(file.Salt, entry, scope, check.Outcome.Violations)
		if err != nil {
			return false, err
		}
		current := make(map[string]struct{}, len(digests))
		for _, digest := range digests {
			current[digest] = struct{}{}
		}
		kept := []string{}
		for _, digest := range file.Checks[index].Fingerprints {
			if _, ok := current[digest]; ok {
				kept = append(kept, digest)
			}
		}
		removed := len(file.Checks[index].Fingerprints) - len(kept)
		if removed > 0 {
			file.Checks[index].Fingerprints = kept
			changed = true
		}
		fprintf(stdout, "%s: checks[%d]: removed %d, kept %d\n", entry.Slug, entry.CheckIndex, removed, len(kept))
	}
	return changed, nil
}

// stampBaseline copies the local file's fingerprints into the compiled entries, as compile does for waivers.
// One entry holds the fingerprints of every scope of its check. The scope feeds the digest, so a run can
// match only its own. It returns one line for each recorded check that has no compiled check.
func stampBaseline(root string, compiled []compiler.Compiled) ([]string, error) {
	file, found, err := baseline.Read(root)
	if err != nil || !found {
		return nil, err
	}
	recorded := map[string][]string{}
	for _, check := range file.Checks {
		key := baselineKey(check.DecisionID, check.CheckIndex)
		recorded[key] = append(recorded[key], check.Fingerprints...)
	}
	for i := range compiled {
		entry := &compiled[i].Entry
		key := baselineKey(entry.DecisionID, entry.CheckIndex)
		digests, ok := recorded[key]
		if !ok {
			continue
		}
		delete(recorded, key)
		if len(digests) > 0 {
			slices.Sort(digests)
			entry.Baseline = &compiler.ManifestBaseline{Salt: file.Salt, Fingerprints: digests}
		}
	}
	var lines []string
	for _, check := range file.Checks {
		key := baselineKey(check.DecisionID, check.CheckIndex)
		if _, unused := recorded[key]; unused {
			delete(recorded, key)
			lines = append(lines, fmt.Sprintf("%s: %s checks[%d] has no compiled check, ignored", baseline.RelPath, compiler.EscapeControls(check.DecisionID), check.CheckIndex))
		}
	}
	return lines, nil
}

func baselineKey(decisionID string, index int) string {
	return fmt.Sprintf("%s/%d", decisionID, index)
}
