package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type hookReply struct {
	Decision      string `json:"decision"`
	Reason        string `json:"reason"`
	SystemMessage string `json:"systemMessage"`
	Specific      struct {
		Event    string `json:"hookEventName"`
		Decision string `json:"permissionDecision"`
		Reason   string `json:"permissionDecisionReason"`
		Context  string `json:"additionalContext"`
	} `json:"hookSpecificOutput"`
}

func callHook(t *testing.T, event map[string]any, args ...string) (hookReply, string) {
	t.Helper()
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := hookCmd(append([]string{"claude-code"}, args...), bytes.NewReader(raw), &stdout, &stderr, mcpTestDeps())
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr.String())
	}
	var reply hookReply
	if stdout.Len() > 0 {
		if err := json.Unmarshal(stdout.Bytes(), &reply); err != nil {
			t.Fatalf("%v: %s", err, stdout.String())
		}
	}
	return reply, stdout.String()
}

func hookFixture(t *testing.T) string {
	t.Helper()
	root := mcpFixture(t)
	writeRuleFile(t, root, ".ipso/config.yaml", "decisions:\n  - docs/decisions/**/*.md\n")
	compileFixture(t)
	return root
}

func preTool(root, tool string, input map[string]any) map[string]any {
	return map[string]any{"hook_event_name": "PreToolUse", "cwd": root, "tool_name": tool, "tool_input": input}
}

func TestHookDeniesAViolatingEditWithADecisionLink(t *testing.T) {
	root := hookFixture(t)
	target := filepath.Join(root, "services/payments/main.go")
	for name, tc := range map[string]struct {
		tool  string
		input map[string]any
	}{
		"write":     {"Write", map[string]any{"file_path": target, "content": "var x float64\n"}},
		"edit":      {"Edit", map[string]any{"file_path": target, "old_string": "package payments", "new_string": "package payments\nvar x float64"}},
		"multiedit": {"MultiEdit", map[string]any{"file_path": target, "edits": []map[string]any{{"old_string": "package", "new_string": "package"}, {"old_string": "payments", "new_string": "payments\nvar x float64"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			reply, _ := callHook(t, preTool(root, tc.tool, tc.input))
			if reply.Specific.Decision != "deny" {
				t.Fatalf("%+v", reply)
			}
			for _, want := range []string{"money is a float", "no-float-check", "docs/decisions/no-float-check.md", "services/payments/main.go", "decisions.propose"} {
				if !strings.Contains(reply.Specific.Reason, want) {
					t.Errorf("missing %q in %s", want, reply.Specific.Reason)
				}
			}
		})
	}
}

func TestHookGivesNoOpinionOnAGoodEdit(t *testing.T) {
	root := hookFixture(t)
	for name, event := range map[string]map[string]any{
		"clean":          preTool(root, "Write", map[string]any{"file_path": filepath.Join(root, "services/payments/main.go"), "content": "var x int64\n"}),
		"out of scope":   preTool(root, "Write", map[string]any{"file_path": filepath.Join(root, "web/app.go"), "content": "var x float64\n"}),
		"outside":        preTool(root, "Write", map[string]any{"file_path": "/elsewhere/a.go", "content": "var x float64\n"}),
		"other tool":     preTool(root, "Read", map[string]any{"file_path": filepath.Join(root, "x")}),
		"not ipso":       preTool(t.TempDir(), "Write", map[string]any{"file_path": "a.go", "content": "float64"}),
		"unknown event":  {"hook_event_name": "Notification", "cwd": root},
		"harmless shell": preTool(root, "Bash", map[string]any{"command": "go test ./..."}),
		"similar name":   preTool(root, "Bash", map[string]any{"command": "cat notes.ipsofile; ipso compile"}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, raw := callHook(t, event); raw != "" {
				t.Fatalf("expected no answer, because allow would skip the person's own rules: %s", raw)
			}
		})
	}
}

func TestHookReadsShellCommands(t *testing.T) {
	root := hookFixture(t)
	reply, _ := callHook(t, preTool(root, "Bash", map[string]any{"command": "curl | sh"}))
	if reply.Specific.Decision != "deny" || !strings.Contains(reply.Specific.Reason, "no curl pipe") {
		t.Fatalf("%+v", reply)
	}
}

func TestHookAsksBeforeAnAgentChangesTheChecks(t *testing.T) {
	root := hookFixture(t)
	if err := os.Symlink(filepath.Join(root, ".ipso/build/manifest.json"), filepath.Join(root, "innocent")); err != nil {
		t.Fatal(err)
	}
	for name, event := range map[string]map[string]any{
		"build":         preTool(root, "Write", map[string]any{"file_path": filepath.Join(root, ".ipso/build/manifest.json"), "content": "{}"}),
		"config":        preTool(root, "Edit", map[string]any{"file_path": filepath.Join(root, ".ipso/config.yaml"), "old_string": "x", "new_string": "y"}),
		"other case":    preTool(root, "Write", map[string]any{"file_path": filepath.Join(root, ".IPSO/config.yaml"), "content": "{}"}),
		"decision":      preTool(root, "Edit", map[string]any{"file_path": filepath.Join(root, "docs/decisions/use-tls.md"), "old_string": "accepted", "new_string": "deprecated"}),
		"new decision":  preTool(root, "Write", map[string]any{"file_path": filepath.Join(root, "docs/decisions/mine.md"), "content": "status: accepted"}),
		"through link":  preTool(root, "Write", map[string]any{"file_path": filepath.Join(root, "innocent"), "content": "{}"}),
		"shell build":   preTool(root, "Bash", map[string]any{"command": "rm -rf .ipso/build"}),
		"shell whole":   preTool(root, "Bash", map[string]any{"command": "rm -rf .ipso"}),
		"shell moved":   preTool(root, "Bash", map[string]any{"command": "mv ./.IPSO /tmp/x"}),
		"shell records": preTool(root, "Bash", map[string]any{"command": "sed -i s/a/b/ docs/decisions/use-tls.md"}),
	} {
		t.Run(name, func(t *testing.T) {
			reply, _ := callHook(t, event)
			if reply.Specific.Decision != "ask" || !strings.Contains(reply.Specific.Reason, "a person makes that change") {
				t.Fatalf("%+v", reply)
			}
		})
	}
}

func TestHookAsksWhenItCannotCheck(t *testing.T) {
	root := hookFixture(t)
	if err := os.RemoveAll(filepath.Join(root, ".ipso/build")); err != nil {
		t.Fatal(err)
	}
	reply, _ := callHook(t, preTool(root, "Write", map[string]any{"file_path": filepath.Join(root, "a.go"), "content": "x"}))
	if reply.Specific.Decision != "ask" || !strings.Contains(reply.Specific.Reason, "ipso compile") {
		t.Fatalf("%+v", reply)
	}
	var stdout, stderr bytes.Buffer
	if code := hookCmd([]string{"claude-code"}, strings.NewReader("not json"), &stdout, &stderr, mcpTestDeps()); code != 0 || !strings.Contains(stdout.String(), `"ask"`) {
		t.Fatalf("code %d: %s", code, stdout.String())
	}
}

func TestHookAsksOnAWarnCheckAndNotesAnAdviseCheck(t *testing.T) {
	for mode, want := range map[string]string{"warn": "ask", "advise": ""} {
		t.Run(mode, func(t *testing.T) {
			root := mcpFixture(t)
			path := filepath.Join(root, "docs/decisions/no-float-check.md")
			text := readRuleFile(t, root, "docs/decisions/no-float-check.md")
			if err := os.WriteFile(path, []byte(strings.Replace(text, "mode: block", "mode: "+mode, 1)), 0o644); err != nil {
				t.Fatal(err)
			}
			writeRuleFile(t, root, ".ipso/config.yaml", "decisions:\n  - docs/decisions/**/*.md\n")
			compileFixture(t)
			reply, _ := callHook(t, preTool(root, "Write", map[string]any{"file_path": filepath.Join(root, "services/a.go"), "content": "float64"}))
			if reply.Specific.Decision != want {
				t.Fatalf("%+v", reply)
			}
			if mode == "advise" && !strings.Contains(reply.Specific.Context, "money is a float") {
				t.Fatalf("%+v", reply)
			}
		})
	}
}

func TestHookWaiverCoversAViolation(t *testing.T) {
	root := mcpFixture(t)
	path := filepath.Join(root, "docs/decisions/no-float-check.md")
	text := readRuleFile(t, root, "docs/decisions/no-float-check.md")
	waiver := "waivers:\n  - approver: team:core\n    reason: migration\n    valid_from: 2026-01-01\n    valid_to: 2026-12-01\n"
	if err := os.WriteFile(path, []byte(strings.Replace(text, "waivers: []\n", waiver, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	writeRuleFile(t, root, ".ipso/config.yaml", "decisions:\n  - docs/decisions/**/*.md\n")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"compile"}, &stdout, &stderr, mcpTestDeps()); code != 0 {
		t.Fatalf("compile: %s %s", stdout.String(), stderr.String())
	}
	if _, raw := callHook(t, preTool(root, "Write", map[string]any{"file_path": filepath.Join(root, "services/a.go"), "content": "float64"})); raw != "" {
		t.Fatalf("a waived violation stops nothing: %s", raw)
	}
}

func hookGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = root
	command.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com", "GIT_CONFIG_GLOBAL=/dev/null")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
}

func TestHookStopGivesViolationsBackOnce(t *testing.T) {
	root := hookFixture(t)
	hookGit(t, root, "init", "-q", ".")
	hookGit(t, root, "add", "-A")
	hookGit(t, root, "commit", "-q", "--no-gpg-sign", "-m", "base")

	stop := map[string]any{"hook_event_name": "Stop", "cwd": root, "stop_hook_active": false}
	if _, raw := callHook(t, stop); raw != "" {
		t.Fatalf("a clean tree: %s", raw)
	}

	writeRuleFile(t, root, "services/payments/main.go", "package payments\nvar x float64\n")
	reply, _ := callHook(t, stop)
	if reply.Decision != "block" || !strings.Contains(reply.Reason, "money is a float") || !strings.Contains(reply.Reason, "no-float-check") {
		t.Fatalf("%+v", reply)
	}

	stop["stop_hook_active"] = true
	reply, _ = callHook(t, stop)
	if reply.Decision != "" || !strings.Contains(reply.SystemMessage, "money is a float") {
		t.Fatalf("a second stop reports and ends: %+v", reply)
	}
}

func TestHookStopReportsAnInvalidDecision(t *testing.T) {
	root := hookFixture(t)
	writeRuleFile(t, root, "docs/decisions/broken.md", "not a decision\n")
	reply, _ := callHook(t, map[string]any{"hook_event_name": "Stop", "cwd": root})
	if reply.Decision != "block" || !strings.Contains(reply.Reason, "broken.md") {
		t.Fatalf("%+v", reply)
	}
}

func TestHookStopSaysWhenAnEngineCannotRun(t *testing.T) {
	root := mcpFixture(t)
	writeRuleFile(t, root, ".ipso/config.yaml", "decisions:\n  - docs/decisions/**/*.md\n")
	writeRuleFile(t, root, "policy/semgrep.yaml", "rules:\n  - id: no-print\n    languages: [python]\n    severity: ERROR\n    message: no print\n    pattern: print(...)\n")
	record := strings.Replace(ruleRecord("semgrep-rule", "Semgrep rule", ruleRepoWide, "", "x"), "checks: []", "checks:\n  - engine: semgrep\n    ref: policy/semgrep.yaml\n    mode: block", 1)
	writeRuleFile(t, root, "docs/decisions/semgrep-rule.md", record)
	compileFixture(t)
	t.Setenv("PATH", t.TempDir())
	reply, raw := callHook(t, map[string]any{"hook_event_name": "Stop", "cwd": root})
	if reply.Decision == "block" || !strings.Contains(reply.SystemMessage, "semgrep") {
		t.Fatalf("a missing engine is not a violation: %s", raw)
	}
}

func TestHookSessionStartCompilesAndStatesDecisions(t *testing.T) {
	root := mcpFixture(t)
	writeRuleFile(t, root, ".ipso/config.yaml", "decisions:\n  - docs/decisions/**/*.md\n")
	reply, _ := callHook(t, map[string]any{"hook_event_name": "SessionStart", "cwd": root, "source": "startup"})
	for _, want := range []string{"`use-tls`: Use TLS everywhere (blocking)", "`no-floats`: No floats for money (blocking, **/*.money, services/payments/**)"} {
		if !strings.Contains(reply.Specific.Context, want) && !strings.Contains(reply.Specific.Context, "`no-floats`: No floats for money (blocking, services/payments/**, **/*.money)") {
			t.Errorf("missing %q in %s", want, reply.Specific.Context)
		}
	}
	if strings.Contains(reply.Specific.Context, "vault.internal") || !strings.Contains(reply.Specific.Context, "`vault-host` (blocking") {
		t.Errorf("sensitive: %s", reply.Specific.Context)
	}
	if strings.Contains(reply.Specific.Context, "Private rationale") {
		t.Errorf("rationale: %s", reply.Specific.Context)
	}
	if _, err := os.Stat(filepath.Join(root, ".ipso/build/manifest.json")); err != nil {
		t.Fatalf("no build after session start: %v", err)
	}
}

func TestHookSessionContextIsBounded(t *testing.T) {
	root := mcpFixture(t)
	writeRuleFile(t, root, ".ipso/config.yaml", "decisions:\n  - docs/decisions/**/*.md\n")
	long := strings.Repeat("A very long decision title ", 30)
	for i := range 60 {
		slug := "bulk-" + strings.Repeat("a", i+1)
		writeRuleFile(t, root, "docs/decisions/"+slug+".md", ruleRecord(slug, long, ruleRepoWide, "", "x"))
	}
	reply, _ := callHook(t, map[string]any{"hook_event_name": "SessionStart", "cwd": root})
	if len(reply.Specific.Context) > 10000 || !strings.Contains(reply.Specific.Context, " more.") {
		t.Fatalf("%d characters", len(reply.Specific.Context))
	}
}

func TestHookUsesASignedBundle(t *testing.T) {
	root := hookFixture(t)
	keyDir := t.TempDir()
	private, public := cliKeys(t)
	layout := filepath.Join(keyDir, "layout")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"bundle", "pack", "--layout", layout}, &stdout, &stderr, mcpTestDeps()); code != 0 {
		t.Fatalf("pack: %s", stderr.String())
	}
	digest := strings.TrimSpace(stdout.String())
	stdout.Reset()
	if code := run([]string{"bundle", "sign", "--layout", layout, "--key", private}, &stdout, &stderr, mcpTestDeps()); code != 0 {
		t.Fatalf("sign: %s", stderr.String())
	}
	if err := os.RemoveAll(filepath.Join(root, ".ipso/build")); err != nil {
		t.Fatal(err)
	}
	event := preTool(root, "Write", map[string]any{"file_path": filepath.Join(root, "services/a.go"), "content": "float64"})
	reply, _ := callHook(t, event, "--bundle", layout, "--digest", digest, "--key", public)
	if reply.Specific.Decision != "deny" {
		t.Fatalf("%+v", reply)
	}
	reply, _ = callHook(t, event, "--bundle", layout, "--digest", "sha256:"+strings.Repeat("0", 64), "--key", public)
	if reply.Specific.Decision != "ask" {
		t.Fatalf("a bad pin must not pass: %+v", reply)
	}
	t.Setenv("CLAUDE_PLUGIN_OPTION_BUNDLE_DIR", layout)
	t.Setenv("CLAUDE_PLUGIN_OPTION_BUNDLE_DIGEST", digest)
	t.Setenv("CLAUDE_PLUGIN_OPTION_BUNDLE_KEY", public)
	if reply, _ = callHook(t, event); reply.Specific.Decision != "deny" {
		t.Fatalf("plugin options: %+v", reply)
	}
}

func TestHookRefusesHalfABundleSetting(t *testing.T) {
	root := hookFixture(t)
	event := preTool(root, "Write", map[string]any{"file_path": filepath.Join(root, "services/a.go"), "content": "int64"})
	for name, args := range map[string][]string{
		"bundle alone": {"--bundle", "x"},
		"digest alone": {"--digest", "sha256:" + strings.Repeat("0", 64)},
		"key alone":    {"--key", "x"},
	} {
		t.Run(name, func(t *testing.T) {
			reply, _ := callHook(t, event, args...)
			if reply.Specific.Decision != "ask" {
				t.Fatalf("this must not fall back to the local build: %+v", reply)
			}
		})
	}
}

func TestClassifyVerdictLine(t *testing.T) {
	for line, want := range map[string]verdictLine{
		"no-print: checks[0] (block): no-print app.py:1":             lineViolation,
		"no-print: checks[0] (block): pass":                          lineOther,
		"no-print: checks[0] (block): waived":                        lineOther,
		"no-print: checks[0] (block): waived (baseline: 2)":          lineOther,
		"no-print: checks[0] (warn): no-print app.py:1":              lineOther,
		"no-print: checks[0] (block): error: semgrep is not on PATH": lineError,
		"no-print: checks[0] (warn): error: semgrep is not on PATH":  lineError,
		"no-print: checks[0] (block): baselined: 2":                  lineOther,
		"no-print: checks[0] (block): waived-looking message":        lineViolation,
		"no checks selected":                                         lineOther,
	} {
		if got := classifyVerdictLine(line); got != want {
			t.Errorf("%q: got %d, want %d", line, got, want)
		}
	}
}

func TestHookUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	for _, args := range [][]string{{}, {"other"}, {"claude-code", "--bundle"}, {"claude-code", "--nope", "x"}} {
		if code := hookCmd(args, strings.NewReader("{}"), &stdout, &stderr, mcpTestDeps()); code != 2 {
			t.Errorf("%v: code %d", args, code)
		}
	}
}

// TestHookLatency measures the hot path through the real binary, one process per edit, the way an
// agent runs it. CI sets IPSO_HOOK_LATENCY to hold it to the 300 ms of section 4.2.
func TestHookLatency(t *testing.T) {
	ipsoOnPath(t)
	root := mcpFixture(t)
	writeRuleFile(t, root, ".ipso/config.yaml", "decisions:\n  - docs/decisions/**/*.md\n")
	for i := range 20 {
		slug := "latency-" + strings.Repeat("a", i+1)
		record := ruleRecord(slug, "Latency", "  - paths: [\"services/**\"]", "", "x")
		record = strings.Replace(record, "checks: []", "checks:\n  - engine: opa\n    target: agent-edit\n    ref: policy/nofloat.rego\n    mode: block", 1)
		writeRuleFile(t, root, "docs/decisions/"+slug+".md", record)
	}
	compileFixture(t)
	event, err := json.Marshal(preTool(root, "Write", map[string]any{"file_path": filepath.Join(root, "services/a.go"), "content": strings.Repeat("var x int64\n", 2000)}))
	if err != nil {
		t.Fatal(err)
	}
	runs := make([]time.Duration, 0, 40)
	for range 40 {
		command := exec.Command("ipso", "hook", "claude-code")
		command.Dir = root
		command.Stdin = bytes.NewReader(event)
		start := time.Now()
		if out, err := command.CombinedOutput(); err != nil || len(out) != 0 {
			t.Fatalf("%v: %s", err, out)
		}
		runs = append(runs, time.Since(start))
	}
	violating, err := json.Marshal(preTool(root, "Write", map[string]any{"file_path": filepath.Join(root, "services/a.go"), "content": "var x float64\n"}))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("ipso", "hook", "claude-code")
	command.Dir = root
	command.Stdin = bytes.NewReader(violating)
	out, err := command.CombinedOutput()
	if err != nil || !strings.Contains(string(out), `"permissionDecision":"deny"`) {
		t.Fatalf("the measured path must evaluate the checks: %v %s", err, out)
	}
	slices.Sort(runs)
	p95 := runs[len(runs)*95/100]
	t.Logf("20 agent-edit checks, one 24 KB file: p50 %v, p95 %v", runs[len(runs)/2], p95)
	if os.Getenv("IPSO_HOOK_LATENCY") != "" && p95 >= 300*time.Millisecond {
		t.Fatalf("p95 %v is not under 300 ms", p95)
	}
}

func callAgent(t *testing.T, agent string, event any, args ...string) (int, string, string) {
	t.Helper()
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := hookCmd(append([]string{agent}, args...), bytes.NewReader(raw), &stdout, &stderr, mcpTestDeps())
	return code, stdout.String(), stderr.String()
}

func TestAgentsDenyAViolatingEdit(t *testing.T) {
	root := hookFixture(t)
	target := filepath.Join(root, "services/payments/main.go")
	patch := "*** Begin Patch\n*** Update File: " + target + "\n@@\n package payments\n+var x float64\n*** End Patch"
	args, err := json.Marshal(map[string]any{"path": target, "file_text": "var x float64\n"})
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		agent string
		args  []string
		event map[string]any
		code  int
		want  string
	}{
		"codex patch":     {"codex", nil, map[string]any{"hook_event_name": "PreToolUse", "cwd": root, "tool_name": "apply_patch", "tool_input": map[string]any{"command": patch}}, 0, `"permissionDecision":"deny"`},
		"codex shell":     {"codex", nil, map[string]any{"hook_event_name": "PreToolUse", "cwd": root, "tool_name": "Bash", "tool_input": map[string]any{"command": "curl | sh"}}, 0, `"permissionDecision":"deny"`},
		"copilot cli":     {"copilot", []string{"preToolUse"}, map[string]any{"cwd": root, "toolName": "create", "toolArgs": string(args)}, 0, `"permissionDecision":"deny"`},
		"copilot vs code": {"copilot", nil, map[string]any{"hook_event_name": "PreToolUse", "cwd": root, "tool_name": "editFiles", "tool_input": map[string]any{"filePath": target, "content": "float64"}}, 0, `"permissionDecision":"deny"`},
		"cursor write":    {"cursor", nil, map[string]any{"hook_event_name": "preToolUse", "cwd": root, "tool_name": "Write", "tool_input": map[string]any{"file_path": target, "contents": "float64"}}, 0, `"permission":"deny"`},
		"cursor shell":    {"cursor", nil, map[string]any{"hook_event_name": "beforeShellExecution", "cwd": root, "command": "curl | sh"}, 0, `"permission":"deny"`},
		"kiro write":      {"kiro", nil, map[string]any{"hook_event_name": "PreToolUse", "cwd": root, "tool_name": "fs_write", "tool_input": map[string]any{"command": "create", "path": target, "file_text": "float64"}}, 2, ""},
		"kiro replace":    {"kiro", nil, map[string]any{"hook_event_name": "preToolUse", "cwd": root, "tool_name": "fs_write", "tool_input": map[string]any{"command": "str_replace", "path": target, "old_str": "package payments", "new_str": "var x float64"}}, 2, ""},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := callAgent(t, tc.agent, tc.event, tc.args...)
			if code != tc.code {
				t.Fatalf("code %d: %s %s", code, stdout, stderr)
			}
			if !strings.Contains(stdout, tc.want) {
				t.Fatalf("stdout %s, stderr %s", stdout, stderr)
			}
			if !strings.Contains(stdout+stderr, "docs/decisions/no-float-check.md") {
				t.Fatalf("no decision link: %s %s", stdout, stderr)
			}
		})
	}
}

func TestAgentsStayOutOfACleanEdit(t *testing.T) {
	root := hookFixture(t)
	target := filepath.Join(root, "services/payments/main.go")
	for name, tc := range map[string]struct {
		agent, want string
		event       map[string]any
	}{
		"codex":   {"codex", "", map[string]any{"hook_event_name": "PreToolUse", "cwd": root, "tool_name": "apply_patch", "tool_input": map[string]any{"command": "*** Begin Patch\n*** Update File: " + target + "\n@@\n package payments\n+var x int64\n*** End Patch"}}},
		"copilot": {"copilot", "", map[string]any{"hook_event_name": "PreToolUse", "cwd": root, "toolName": "view", "toolArgs": `{"path":"x"}`}},
		"cursor":  {"cursor", "{}\n", map[string]any{"hook_event_name": "preToolUse", "cwd": root, "tool_name": "Write", "tool_input": map[string]any{"file_path": target, "contents": "int64"}}},
		"kiro":    {"kiro", "", map[string]any{"hook_event_name": "PreToolUse", "cwd": root, "tool_name": "fs_read", "tool_input": map[string]any{"path": target}}},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := callAgent(t, tc.agent, tc.event)
			if code != 0 || stdout != tc.want {
				t.Fatalf("code %d, stdout %q, stderr %q", code, stdout, stderr)
			}
		})
	}
}

// An agent with no working ask must not let a protected edit through.
func TestAgentsWithNoAskRefuseAProtectedEdit(t *testing.T) {
	root := hookFixture(t)
	record := filepath.Join(root, "docs/decisions/use-tls.md")
	for name, tc := range map[string]struct {
		agent string
		event map[string]any
		code  int
		want  string
	}{
		"claude keeps ask":  {"claude-code", map[string]any{"hook_event_name": "PreToolUse", "cwd": root, "tool_name": "Write", "tool_input": map[string]any{"file_path": record, "content": "x"}}, 0, `"permissionDecision":"ask"`},
		"codex":             {"codex", map[string]any{"hook_event_name": "PreToolUse", "cwd": root, "tool_name": "apply_patch", "tool_input": map[string]any{"command": "*** Begin Patch\n*** Delete File: " + record + "\n*** End Patch"}}, 0, `"permissionDecision":"deny"`},
		"copilot keeps ask": {"copilot", map[string]any{"hook_event_name": "PreToolUse", "cwd": root, "toolName": "edit", "toolArgs": `{"path":"` + record + `","old_str":"a","new_str":"b"}`}, 0, `"permissionDecision":"ask"`},
		"cursor edit":       {"cursor", map[string]any{"hook_event_name": "preToolUse", "cwd": root, "tool_name": "Delete", "tool_input": map[string]any{"file_path": record}}, 0, `"permission":"deny"`},
		"cursor shell asks": {"cursor", map[string]any{"hook_event_name": "beforeShellExecution", "cwd": root, "command": "rm -rf .ipso"}, 0, `"permission":"ask"`},
		"kiro":              {"kiro", map[string]any{"hook_event_name": "PreToolUse", "cwd": root, "tool_name": "delete_file", "tool_input": map[string]any{"path": record}}, 2, ""},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := callAgent(t, tc.agent, tc.event)
			if code != tc.code || !strings.Contains(stdout, tc.want) {
				t.Fatalf("code %d, stdout %q, stderr %q", code, stdout, stderr)
			}
		})
	}
}

func TestAgentsCodexPatchThatCannotBeReadIsNotAPass(t *testing.T) {
	root := hookFixture(t)
	code, stdout, _ := callAgent(t, "codex", map[string]any{"hook_event_name": "PreToolUse", "cwd": root, "tool_name": "apply_patch", "tool_input": map[string]any{"command": "not a patch"}})
	if code != 0 || !strings.Contains(stdout, `"permissionDecision":"deny"`) {
		t.Fatalf("code %d: %s", code, stdout)
	}
}

func TestAgentsStopAndSession(t *testing.T) {
	root := hookFixture(t)
	hookGit(t, root, "init", "-q", ".")
	hookGit(t, root, "add", "-A")
	hookGit(t, root, "commit", "-q", "--no-gpg-sign", "-m", "base")
	writeRuleFile(t, root, "services/payments/main.go", "package payments\nvar x float64\n")

	for name, tc := range map[string]struct {
		agent string
		args  []string
		event map[string]any
		want  string
	}{
		"codex":           {"codex", nil, map[string]any{"hook_event_name": "Stop", "cwd": root}, `"decision":"block"`},
		"copilot":         {"copilot", []string{"agentStop"}, map[string]any{"cwd": root, "stop_hook_active": false}, `"decision":"block"`},
		"cursor":          {"cursor", nil, map[string]any{"hook_event_name": "stop", "workspace_roots": []string{root}, "loop_count": 0}, `"followup_message"`},
		"kiro":            {"kiro", nil, map[string]any{"hook_event_name": "Stop", "cwd": root}, "money is a float"},
		"codex session":   {"codex", nil, map[string]any{"hook_event_name": "SessionStart", "cwd": root}, `"additionalContext"`},
		"copilot session": {"copilot", []string{"sessionStart"}, map[string]any{"cwd": root}, `"additionalContext"`},
		"cursor session":  {"cursor", nil, map[string]any{"hook_event_name": "sessionStart", "workspace_roots": []string{root}}, `"additional_context"`},
		"kiro session":    {"kiro", nil, map[string]any{"hook_event_name": "SessionStart", "cwd": root}, "use-tls"},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := callAgent(t, tc.agent, tc.event, tc.args...)
			if code != 0 || !strings.Contains(stdout, tc.want) {
				t.Fatalf("code %d, stdout %q, stderr %q", code, stdout, stderr)
			}
		})
	}

	// The second round reports and lets the session end, so the agent and the hook cannot loop.
	if _, stdout, _ := callAgent(t, "cursor", map[string]any{"hook_event_name": "stop", "workspace_roots": []string{root}, "loop_count": 1}); stdout != "{}\n" {
		t.Errorf("cursor second round: %s", stdout)
	}
	if _, stdout, stderr := callAgent(t, "copilot", map[string]any{"cwd": root, "stop_hook_active": true}, "agentStop"); stdout != "" || !strings.Contains(stderr, "money is a float") {
		t.Errorf("copilot second round: %q %q", stdout, stderr)
	}
}

func TestAgentsIgnoreClaudeOptionsInTheEnvironment(t *testing.T) {
	root := hookFixture(t)
	t.Setenv("CLAUDE_PLUGIN_OPTION_BUNDLE_KEY", "/nowhere")
	code, stdout, stderr := callAgent(t, "codex", map[string]any{"hook_event_name": "PreToolUse", "cwd": root, "tool_name": "Bash", "tool_input": map[string]any{"command": "ls"}})
	if code != 0 || stdout != "" {
		t.Fatalf("code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}
