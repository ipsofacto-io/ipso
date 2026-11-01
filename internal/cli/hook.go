package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ipsofacto-io/ipso/internal/bundle"
	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/config"
	"github.com/ipsofacto-io/ipso/internal/edit"
	"github.com/ipsofacto-io/ipso/internal/edr"
	"github.com/ipsofacto-io/ipso/internal/hook"
	"github.com/ipsofacto-io/ipso/internal/rules"
)

const (
	hookUsage = "usage: ipso hook claude-code|codex|copilot|cursor|kiro [event] [--bundle dir --digest sha256:hex --key public.pem]"
	// maxHookInput bounds the event an agent sends. A Write event carries the whole file.
	maxHookInput = 64 << 20
	// maxHookFile is the largest file the hook reads to work out the content after an edit.
	maxHookFile = 8 << 20
	// maxSessionContext stays under the 10,000 characters Claude Code keeps from a hook.
	maxSessionContext = 9000
)

// hookEngines are the engines a Stop hook can run on a whole tree. The rest need an input a hook
// does not have, such as a plan, compiled classes, or a CI evidence file.
var hookEngines = []struct{ engine, target, command string }{
	{"semgrep", "", "semgrep"},
	{"depcruise", "", "depcruise"},
	{"eslint", "", "eslint"},
	{"kyverno", "", "kyverno"},
	{"opa", "gatekeeper", "gatekeeper"},
}

type hookOptions struct {
	bundle string
	digest string
	key    string
}

// hookCmd answers one agent event from stdin. An unexpected failure asks a person rather than
// failing open or stopping all work. The answer is on stdout, or in the exit code for an agent that
// has no other way to refuse.
func hookCmd(args []string, stdin io.Reader, stdout, stderr io.Writer, d deps) int {
	if len(args) == 0 {
		fprintln(stderr, hookUsage)
		return 2
	}
	agent, ok := hookAgents[args[0]]
	if !ok {
		fprintln(stderr, hookUsage)
		return 2
	}
	rest := args[1:]
	named := ""
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		named, rest = rest[0], rest[1:]
	}
	getenv := func(string) string { return "" }
	if args[0] == "claude-code" {
		getenv = os.Getenv
	}
	opts, err := parseHookArgs(rest, getenv)
	if err != nil {
		fprintln(stderr, err)
		return 2
	}
	if d.now == nil {
		d.now = time.Now
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, maxHookInput+1))
	if err == nil && len(raw) > maxHookInput {
		err = errors.New("the hook event is too large")
	}
	var event agentEvent
	if err == nil {
		event, err = decodeAgentEvent(raw, named)
	}
	if err != nil {
		return agent.tool(stdout, stderr, event, hook.Decision{Action: hook.Ask, Reason: "ipso: could not read the hook event: " + compiler.EscapeControls(err.Error())})
	}
	switch event.kind {
	case eventTool:
		return agent.tool(stdout, stderr, event, editDecision(event, opts, d))
	case eventStop:
		root, ok := hookRoot(event.cwd)
		if !ok {
			return agent.stop(stdout, stderr, event, nil, nil)
		}
		violations, notes := fullCheck(root, opts, d)
		return agent.stop(stdout, stderr, event, violations, notes)
	case eventSession:
		root, ok := hookRoot(event.cwd)
		if !ok {
			return agent.session(stdout, "")
		}
		return agent.session(stdout, sessionText(root, opts, d))
	}
	return 0
}

// parseHookArgs takes the bundle from flags, or from the options Claude Code exports to a plugin's
// hook processes. An agent's shell tool cannot set the environment of a hook.
func parseHookArgs(args []string, getenv func(string) string) (hookOptions, error) {
	opts := hookOptions{
		bundle: getenv("CLAUDE_PLUGIN_OPTION_BUNDLE_DIR"),
		digest: getenv("CLAUDE_PLUGIN_OPTION_BUNDLE_DIGEST"),
		key:    getenv("CLAUDE_PLUGIN_OPTION_BUNDLE_KEY"),
	}
	for i := 0; i < len(args); i += 2 {
		if i+1 >= len(args) {
			return hookOptions{}, errors.New(hookUsage)
		}
		switch args[i] {
		case "--bundle":
			opts.bundle = args[i+1]
		case "--digest":
			opts.digest = args[i+1]
		case "--key":
			opts.key = args[i+1]
		default:
			return hookOptions{}, errors.New(hookUsage)
		}
	}
	return opts, nil
}

// load refuses half of a bundle setting. Falling back to the local build would quietly replace a
// signed policy with one the repository can change.
func (o hookOptions) load(root string) (compiler.Build, error) {
	if o.bundle != "" {
		return bundle.Verify(o.bundle, o.digest, o.key)
	}
	if o.digest != "" || o.key != "" {
		return compiler.Build{}, errors.New("a bundle digest or key is set with no bundle")
	}
	return compiler.LoadBuild(root)
}

// hookRoot is the nearest directory above dir with ipso config. false means this is not an ipso
// repository, and the hook has no opinion.
func hookRoot(dir string) (string, bool) {
	if dir == "" {
		var err error
		if dir, err = os.Getwd(); err != nil {
			return "", false
		}
	}
	for {
		if info, err := os.Lstat(filepath.Join(dir, ".ipso")); err == nil && info.IsDir() {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// editDecision is the one answer every agent gets for a proposed edit.
func editDecision(event agentEvent, opts hookOptions, d deps) hook.Decision {
	root, ok := hookRoot(event.cwd)
	if !ok {
		return hook.Decision{}
	}
	cfg, _, err := config.Load(root)
	if err != nil {
		return askAbout("could not read the config", err)
	}
	proposals, protected, err := toolProposals(root, event, hook.Protection{DecisionGlobs: cfg.Decisions})
	if err != nil {
		return askAbout("could not read the edit", err)
	}
	if protected {
		return hook.Decision{Action: hook.Ask, Reason: hook.ProtectedReason}
	}
	if len(proposals) == 0 {
		return hook.Decision{}
	}
	build, err := opts.load(root)
	if err != nil {
		return hook.Decision{Action: hook.Ask, Reason: "ipso: the checks could not be loaded, so this edit was not checked: " + compiler.EscapeControls(err.Error()) + ". Run ipso compile."}
	}
	decision, err := hook.Evaluate(build, proposals, d.now())
	if err != nil {
		return askAbout("the checks could not be read", err)
	}
	return decision
}

func askAbout(what string, err error) hook.Decision {
	return hook.Decision{Action: hook.Ask, Reason: "ipso: " + what + ": " + compiler.EscapeControls(err.Error())}
}

// toolProposals turns one tool call into proposed edits. A tool that edits nothing, or a path
// outside the repository, gives no proposal. The second result says a protected path is involved.
func toolProposals(root string, event agentEvent, protection hook.Protection) ([]edit.Proposal, bool, error) {
	call := classifyTool(event.tool, event.input)
	if call.shell != "" {
		if protection.CommandTouchesProtected(call.shell) {
			return nil, true, nil
		}
		return []edit.Proposal{{Tool: "shell", Command: call.shell}}, false, nil
	}
	relative := func(name string) (string, bool) {
		if !filepath.IsAbs(name) && event.cwd != "" {
			name = filepath.Join(event.cwd, name)
		}
		rel, err := repoRelative(root, resolveEditTarget(name))
		return rel, err == nil
	}
	if call.patch != "" {
		parsed, err := edit.FromCodexPatch(func(name string) string {
			rel, ok := relative(name)
			if !ok {
				return ""
			}
			return readForEdit(root, rel)
		}, call.patch)
		if err != nil {
			return nil, false, err
		}
		var proposals []edit.Proposal
		for _, proposal := range parsed {
			rel, ok := relative(proposal.Path)
			if !ok {
				continue
			}
			if protection.Protected(rel) {
				return nil, true, nil
			}
			proposal.Path = rel
			proposals = append(proposals, proposal)
		}
		return proposals, false, nil
	}
	if call.path == "" {
		return nil, false, nil
	}
	rel, ok := relative(call.path)
	if !ok {
		return nil, false, nil
	}
	if protection.Protected(rel) {
		return nil, true, nil
	}
	proposal := edit.Proposal{Path: rel, Tool: call.kind}
	switch {
	case call.kind == "delete":
	case call.replaces:
		current := readForEdit(root, rel)
		for _, item := range call.edits {
			count := 1
			if item.all {
				count = -1
			}
			// An empty old text would match between every character.
			if item.old == "" {
				current += item.new
			} else {
				current = strings.Replace(current, item.old, item.new, count)
			}
			proposal.Added = strings.TrimPrefix(proposal.Added+"\n"+item.new, "\n")
		}
		proposal.Content = current
	default:
		proposal.Content = call.content
		proposal.Added = call.content
	}
	return []edit.Proposal{proposal}, false, nil
}

// resolveEditTarget follows links, so an edit through a link is judged by the file it changes. The
// file may not exist yet, and then its directory is resolved.
func resolveEditTarget(target string) string {
	if resolved, err := filepath.EvalSymlinks(target); err == nil {
		return resolved
	}
	if dir, err := filepath.EvalSymlinks(filepath.Dir(target)); err == nil {
		return filepath.Join(dir, filepath.Base(target))
	}
	return target
}

// readForEdit returns the current file, or "" when it cannot be read. A check then still sees the
// new text, which is what the edit adds.
func readForEdit(root, rel string) string {
	repo, err := os.OpenRoot(root)
	if err != nil {
		return ""
	}
	defer func() { _ = repo.Close() }()
	info, err := repo.Stat(rel)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxHookFile {
		return ""
	}
	data, err := repo.ReadFile(rel)
	if err != nil {
		return ""
	}
	return string(data)
}

// fullCheck returns blocking violations and notes about what could not run. A missing engine is a
// note and not a violation, because the agent cannot fix it and CI still runs it.
func fullCheck(root string, opts hookOptions, d deps) ([]string, []string) {
	var violations, notes []string
	cfg, _, err := config.Load(root)
	if err != nil {
		return nil, []string{compiler.EscapeControls(err.Error())}
	}
	_, problems, err := edr.Load(root, cfg.Decisions)
	if err != nil {
		return nil, []string{compiler.EscapeControls(err.Error())}
	}
	for _, problem := range problems {
		violations = append(violations, compiler.EscapeControls(problem))
	}
	build, err := opts.load(root)
	if err != nil {
		return violations, append(notes, "the checks could not be loaded: "+compiler.EscapeControls(err.Error()))
	}

	proposals, err := changedProposals(root)
	if err != nil {
		notes = append(notes, "agent-edit checks did not run: "+compiler.EscapeControls(err.Error()))
	} else if len(proposals) > 0 {
		decision, err := hook.Evaluate(build, proposals, d.now())
		switch {
		case err != nil:
			notes = append(notes, compiler.EscapeControls(err.Error()))
		case decision.Action == hook.Deny:
			violations = append(violations, decision.Reason)
		case decision.Action == hook.Ask:
			notes = append(notes, decision.Reason)
		}
	}

	// run reads the working directory as the repository root, and a hook process is short lived.
	if err := os.Chdir(root); err != nil {
		return violations, append(notes, compiler.EscapeControls(err.Error()))
	}
	for _, engine := range hookEngines {
		if !buildHasEngine(build, engine.engine, engine.target) {
			continue
		}
		if opts.bundle != "" {
			notes = append(notes, engine.command+" checks did not run, because they read the local build and this session uses a signed bundle")
			continue
		}
		var out, errOut bytes.Buffer
		code := run([]string{"check", engine.command, "."}, &out, &errOut, d)
		if code == 0 {
			continue
		}
		found := false
		for _, line := range outputLines(out.String()) {
			switch classifyVerdictLine(line) {
			case lineViolation:
				violations = append(violations, compiler.EscapeControls(line))
				found = true
			case lineError:
				notes = append(notes, compiler.EscapeControls(line))
				found = true
			}
		}
		if text := strings.TrimSpace(errOut.String()); text != "" {
			notes = append(notes, engine.command+": "+compiler.EscapeControls(text))
			found = true
		}
		if !found {
			notes = append(notes, engine.command+" failed")
		}
	}
	return violations, notes
}

type verdictLine int

const (
	lineOther verdictLine = iota
	lineViolation
	lineError
)

// classifyVerdictLine reads one line of an engine check: "<slug>: checks[N] (mode): <rest>". Only a
// violation in block mode goes back to the agent. pass and waived lines stand next to it when one
// other check failed.
func classifyVerdictLine(line string) verdictLine {
	_, afterIndex, ok := strings.Cut(line, ": checks[")
	if !ok {
		return lineOther
	}
	_, after, ok := strings.Cut(afterIndex, "): ")
	if !ok {
		return lineOther
	}
	if strings.HasPrefix(after, "error: ") {
		return lineError
	}
	if after == "pass" || after == "waived" || strings.HasPrefix(after, "waived (baseline: ") || strings.HasPrefix(after, "baselined: ") {
		return lineOther
	}
	if !strings.Contains(afterIndex, "(block): ") {
		return lineOther
	}
	return lineViolation
}

func buildHasEngine(build compiler.Build, engine, target string) bool {
	return slices.ContainsFunc(build.Entries, func(entry compiler.Entry) bool {
		return entry.Engine == engine && (target == "" && entry.Target != "gatekeeper" || entry.Target == target)
	})
}

// changedProposals reads what git reports as changed. fsmonitor and hooks are turned off for this one
// command, and the environment that points git elsewhere is dropped. A clean filter in .git/config can
// still run, and only the person or agent who already runs commands here can write that file.
func changedProposals(root string) ([]edit.Proposal, error) {
	command := exec.Command("git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames")
	command.Dir = root
	command.Env = slices.DeleteFunc(os.Environ(), func(item string) bool { return strings.HasPrefix(item, "GIT_") })
	out, err := command.Output()
	if err != nil {
		var missing *exec.Error
		if errors.As(err, &missing) {
			return nil, errors.New("git is not on PATH")
		}
		return nil, fmt.Errorf("git status: %w", err)
	}
	var proposals []edit.Proposal
	for _, record := range strings.Split(string(out), "\x00") {
		if len(record) < 4 || record[0] == 'D' || record[1] == 'D' {
			continue
		}
		rel := record[3:]
		if !fs.ValidPath(rel) {
			continue
		}
		content := readForEdit(root, rel)
		proposals = append(proposals, edit.Proposal{Tool: "working-tree", Path: rel, Content: content, Added: content})
	}
	return proposals, nil
}

// sessionText refreshes the local build, which git ignores, so a fresh clone has checks to evaluate.
// It then states the decisions in force. A signed bundle is never replaced.
func sessionText(root string, opts hookOptions, d deps) string {
	var notes []string
	if opts.bundle == "" {
		var out, errOut bytes.Buffer
		if err := os.Chdir(root); err != nil {
			notes = append(notes, compiler.EscapeControls(err.Error()))
		} else if code := run([]string{"compile"}, &out, &errOut, d); code != 0 {
			notes = append(notes, "ipso compile failed, so edits will stop for a person until it succeeds.")
		}
	}
	cfg, _, err := config.Load(root)
	if err != nil {
		return strings.Join(append(notes, compiler.EscapeControls(err.Error())), "\n")
	}
	loaded, problems, err := edr.LoadInForce(root, cfg.Decisions, d.now())
	if err != nil {
		notes = append(notes, compiler.EscapeControls(err.Error()))
	}
	if len(problems) > 0 {
		notes = append(notes, fmt.Sprintf("%d problems in decision files. Run ipso check.", len(problems)))
	}
	return sessionContext(loaded, notes)
}

func sessionContext(loaded []edr.Loaded, notes []string) string {
	var out strings.Builder
	if len(loaded) > 0 {
		out.WriteString("This repository has engineering decisions in force, which ipso enforces on edits. The decisions.applicable and decisions.get tools return their text.\n")
	}
	written := 0
	for _, item := range loaded {
		line := "- `" + item.Rec.Slug + "`"
		if !slices.Contains(item.Rec.Tags, rules.SensitiveTag) {
			line += ": " + compiler.EscapeControls(item.Doc.Title())
		}
		line += " (" + item.Rec.Criticality
		var globs []string
		wide := false
		for _, scope := range item.Rec.Scope {
			wide = wide || len(scope.Paths) == 0
			globs = appendNew(globs, scope.Paths)
		}
		if !wide && len(globs) > 0 {
			line += ", " + compiler.EscapeControls(strings.Join(globs, ", "))
		}
		line += ")\n"
		if out.Len()+len(line) > maxSessionContext {
			fmt.Fprintf(&out, "and %d more.\n", len(loaded)-written)
			break
		}
		out.WriteString(line)
		written++
	}
	for _, note := range notes {
		out.WriteString(note + "\n")
	}
	return out.String()
}

func writeJSON(stdout io.Writer, value any) {
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}
