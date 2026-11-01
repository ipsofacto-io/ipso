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
	hookUsage = "usage: ipso hook claude-code [--bundle dir --digest sha256:hex --key public.pem]"
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
// failing open or stopping all work. Exit 0 is the rule, because the answer is on stdout.
func hookCmd(args []string, stdin io.Reader, stdout, stderr io.Writer, d deps) int {
	if len(args) == 0 || args[0] != "claude-code" {
		fprintln(stderr, hookUsage)
		return 2
	}
	opts, err := parseHookArgs(args[1:], os.Getenv)
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
	var event claudeEvent
	if err == nil {
		err = json.Unmarshal(raw, &event)
	}
	if err != nil {
		writeClaudeAsk(stdout, "ipso: could not read the hook event: "+compiler.EscapeControls(err.Error()))
		return 0
	}
	switch event.HookEventName {
	case "PreToolUse":
		answerPreToolUse(event, opts, stdout, d)
	case "Stop":
		answerStop(event, opts, stdout, d)
	case "SessionStart":
		answerSessionStart(event, opts, stdout, d)
	}
	return 0
}

// parseHookArgs takes the bundle from flags, or from the plugin's options, which Claude Code exports
// to hook processes. An agent's shell tool cannot set the environment of a hook.
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

// claudeEvent is the part of a Claude Code hook event that ipso reads.
type claudeEvent struct {
	HookEventName  string          `json:"hook_event_name"`
	Cwd            string          `json:"cwd"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	StopHookActive bool            `json:"stop_hook_active"`
	Source         string          `json:"source"`
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

func answerPreToolUse(event claudeEvent, opts hookOptions, stdout io.Writer, d deps) {
	root, ok := hookRoot(event.Cwd)
	if !ok {
		return
	}
	cfg, _, err := config.Load(root)
	if err != nil {
		writeClaudeAsk(stdout, "ipso: could not read the config: "+compiler.EscapeControls(err.Error()))
		return
	}
	protection := hook.Protection{DecisionGlobs: cfg.Decisions}
	proposals, protected, err := claudeProposals(root, event, protection)
	if err != nil {
		writeClaudeAsk(stdout, "ipso: could not read the edit: "+compiler.EscapeControls(err.Error()))
		return
	}
	if protected {
		writeClaudeAsk(stdout, hook.ProtectedReason)
		return
	}
	if len(proposals) == 0 {
		return
	}
	build, err := opts.load(root)
	if err != nil {
		writeClaudeAsk(stdout, "ipso: the checks could not be loaded, so this edit was not checked: "+compiler.EscapeControls(err.Error())+". Run ipso compile.")
		return
	}
	decision, err := hook.Evaluate(build, proposals, d.now())
	if err != nil {
		writeClaudeAsk(stdout, "ipso: the checks could not be read: "+compiler.EscapeControls(err.Error()))
		return
	}
	switch decision.Action {
	case hook.Deny:
		writeClaudeDecision(stdout, "deny", decision.Reason, decision.Note)
	case hook.Ask:
		writeClaudeDecision(stdout, "ask", decision.Reason, decision.Note)
	default:
		if decision.Note != "" {
			writeJSON(stdout, map[string]any{"hookSpecificOutput": map[string]any{"hookEventName": "PreToolUse", "additionalContext": decision.Note}})
		}
	}
}

// claudeProposals turns one tool call into proposed edits. A tool that edits nothing, or a path
// outside the repository, gives no proposal.
func claudeProposals(root string, event claudeEvent, protection hook.Protection) ([]edit.Proposal, bool, error) {
	var input struct {
		FilePath     string `json:"file_path"`
		NotebookPath string `json:"notebook_path"`
		Content      string `json:"content"`
		OldString    string `json:"old_string"`
		NewString    string `json:"new_string"`
		NewSource    string `json:"new_source"`
		ReplaceAll   bool   `json:"replace_all"`
		Command      string `json:"command"`
		Edits        []struct {
			OldString  string `json:"old_string"`
			NewString  string `json:"new_string"`
			ReplaceAll bool   `json:"replace_all"`
		} `json:"edits"`
	}
	switch event.ToolName {
	case "Write", "Edit", "MultiEdit", "NotebookEdit", "Bash":
	default:
		return nil, false, nil
	}
	if len(event.ToolInput) > 0 {
		if err := json.Unmarshal(event.ToolInput, &input); err != nil {
			return nil, false, err
		}
	}
	if event.ToolName == "Bash" {
		if input.Command == "" {
			return nil, false, nil
		}
		if protection.CommandTouchesProtected(input.Command) {
			return nil, true, nil
		}
		return []edit.Proposal{{Tool: "shell", Command: input.Command}}, false, nil
	}

	target := input.FilePath
	if event.ToolName == "NotebookEdit" {
		target = input.NotebookPath
	}
	if target == "" {
		return nil, false, nil
	}
	if !filepath.IsAbs(target) && event.Cwd != "" {
		target = filepath.Join(event.Cwd, target)
	}
	rel, err := repoRelative(root, resolveEditTarget(target))
	if err != nil {
		return nil, false, nil
	}
	if protection.Protected(rel) {
		return nil, true, nil
	}
	proposal := edit.Proposal{Path: rel}
	switch event.ToolName {
	case "Write":
		proposal.Tool = "write"
		proposal.Content = input.Content
		proposal.Added = input.Content
	case "NotebookEdit":
		proposal.Tool = "notebook"
		proposal.Content = input.NewSource
		proposal.Added = input.NewSource
	default:
		proposal.Tool = "edit"
		current := readForEdit(root, rel)
		apply := func(oldText, newText string, all bool) {
			count := 1
			if all {
				count = -1
			}
			// An empty old text would match between every character.
			if oldText == "" {
				current += newText
			} else {
				current = strings.Replace(current, oldText, newText, count)
			}
			proposal.Added = strings.TrimPrefix(proposal.Added+"\n"+newText, "\n")
		}
		if event.ToolName == "Edit" {
			apply(input.OldString, input.NewString, input.ReplaceAll)
		}
		for _, item := range input.Edits {
			apply(item.OldString, item.NewString, item.ReplaceAll)
		}
		proposal.Content = current
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

// answerStop runs the checks a hook can run on the working tree and gives blocking violations back
// to the agent to fix. When the agent is already continuing from this hook, it reports and lets the
// session end, so the two cannot loop. CI remains the gate.
func answerStop(event claudeEvent, opts hookOptions, stdout io.Writer, d deps) {
	root, ok := hookRoot(event.Cwd)
	if !ok {
		return
	}
	violations, notes := fullCheck(root, opts, d)
	switch {
	case len(violations) == 0 && len(notes) == 0:
	case len(violations) == 0:
		writeJSON(stdout, map[string]any{"systemMessage": "ipso: " + strings.Join(notes, "\n")})
	case event.StopHookActive:
		writeJSON(stdout, map[string]any{"systemMessage": "ipso: violations remain and CI will report them.\n" + strings.Join(violations, "\n")})
	default:
		writeJSON(stdout, map[string]any{"decision": "block", "reason": "ipso: the working tree violates decisions in force. Fix these, or use the decisions.propose tool to change a decision.\n" + strings.Join(append(violations, notes...), "\n")})
	}
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

// answerSessionStart refreshes the local build, which git ignores, so a fresh clone has checks to
// evaluate. It then states the decisions in force. A signed bundle is never replaced.
func answerSessionStart(event claudeEvent, opts hookOptions, stdout io.Writer, d deps) {
	root, ok := hookRoot(event.Cwd)
	if !ok {
		return
	}
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
		notes = append(notes, compiler.EscapeControls(err.Error()))
		writeClaudeContext(stdout, strings.Join(notes, "\n"))
		return
	}
	loaded, problems, err := edr.LoadInForce(root, cfg.Decisions, d.now())
	if err != nil {
		notes = append(notes, compiler.EscapeControls(err.Error()))
	}
	if len(problems) > 0 {
		notes = append(notes, fmt.Sprintf("%d problems in decision files. Run ipso check.", len(problems)))
	}
	writeClaudeContext(stdout, sessionContext(loaded, notes))
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

func writeClaudeContext(stdout io.Writer, text string) {
	if text == "" {
		return
	}
	writeJSON(stdout, map[string]any{"hookSpecificOutput": map[string]any{"hookEventName": "SessionStart", "additionalContext": text}})
}

func writeClaudeAsk(stdout io.Writer, reason string) {
	writeClaudeDecision(stdout, "ask", reason, "")
}

func writeClaudeDecision(stdout io.Writer, decision, reason, note string) {
	output := map[string]any{"hookEventName": "PreToolUse", "permissionDecision": decision, "permissionDecisionReason": reason}
	if note != "" {
		output["additionalContext"] = note
	}
	writeJSON(stdout, map[string]any{"hookSpecificOutput": output})
}

func writeJSON(stdout io.Writer, value any) {
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}
