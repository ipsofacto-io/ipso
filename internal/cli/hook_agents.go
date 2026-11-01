package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ipsofacto-io/ipso/internal/hook"
)

const (
	eventTool    = "tool"
	eventStop    = "stop"
	eventSession = "session"
)

// agentEvent is one hook event in the terms every agent shares.
type agentEvent struct {
	kind       string
	name       string
	cwd        string
	tool       string
	input      map[string]any
	stopActive bool
}

// hookAgent is how one agent is answered. Each agent's refusal and context differ, and the decision
// behind them does not (ADR-0075).
type hookAgent struct {
	tool    func(stdout, stderr io.Writer, event agentEvent, decision hook.Decision) int
	stop    func(stdout, stderr io.Writer, event agentEvent, violations, notes []string) int
	session func(stdout io.Writer, text string) int
}

var hookAgents = map[string]hookAgent{
	"claude-code": {tool: claudeTool(false), stop: claudeStop, session: claudeSession},
	// Codex marks a hook failed on ask and lets the tool run, so ask has to become deny.
	"codex":   {tool: claudeTool(true), stop: claudeStop, session: claudeSession},
	"copilot": {tool: copilotTool, stop: copilotStop, session: copilotSession},
	"cursor":  {tool: cursorTool, stop: cursorStop, session: cursorSession},
	"kiro":    {tool: kiroTool, stop: kiroStop, session: kiroSession},
}

// decodeAgentEvent accepts the field names the agents use for the same things. named is the event
// from the command line, for an agent whose payload does not state it.
func decodeAgentEvent(raw []byte, named string) (agentEvent, error) {
	var fields struct {
		HookEventName  string          `json:"hook_event_name"`
		Cwd            string          `json:"cwd"`
		WorkspaceRoots []string        `json:"workspace_roots"`
		ToolName       string          `json:"tool_name"`
		ToolNameCamel  string          `json:"toolName"`
		ToolInput      json.RawMessage `json:"tool_input"`
		ToolArgs       json.RawMessage `json:"toolArgs"`
		Command        string          `json:"command"`
		StopHookActive bool            `json:"stop_hook_active"`
		LoopCount      int             `json:"loop_count"`
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return agentEvent{}, err
	}
	event := agentEvent{name: strings.ToLower(named), cwd: fields.Cwd, tool: fields.ToolName, stopActive: fields.StopHookActive || fields.LoopCount > 0}
	if event.name == "" {
		event.name = strings.ToLower(fields.HookEventName)
	}
	if event.cwd == "" && len(fields.WorkspaceRoots) > 0 {
		event.cwd = fields.WorkspaceRoots[0]
	}
	if event.tool == "" {
		event.tool = fields.ToolNameCamel
	}
	switch event.name {
	case "pretooluse":
		event.kind = eventTool
	case "beforeshellexecution":
		event.kind = eventTool
		event.tool = "shell"
		event.input = map[string]any{"command": fields.Command}
		return event, nil
	case "stop", "agentstop":
		event.kind = eventStop
	case "sessionstart", "agentspawn":
		event.kind = eventSession
	}
	input := fields.ToolInput
	if len(input) == 0 {
		input = fields.ToolArgs
	}
	var err error
	event.input, err = decodeToolInput(input)
	return event, err
}

// decodeToolInput reads an object, or an object encoded in a string, which is how the Copilot CLI
// sends toolArgs.
func decodeToolInput(raw json.RawMessage) (map[string]any, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	if raw[0] == '"' {
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return nil, err
		}
		raw = []byte(text)
	}
	var input map[string]any
	if err := json.Unmarshal(raw, &input); err != nil {
		return nil, fmt.Errorf("tool input: %w", err)
	}
	return input, nil
}

type textEdit struct {
	old string
	new string
	all bool
}

// toolCall is what a tool call does to the repository. An empty one edits nothing ipso can see.
type toolCall struct {
	shell    string
	patch    string
	path     string
	kind     string
	content  string
	replaces bool
	edits    []textEdit
}

// classifyTool reads a call by its shape, because the agents name the same fields differently and
// not all document them. A tool whose shape is not known gives no proposal, and CI still checks it.
func classifyTool(tool string, input map[string]any) toolCall {
	name := strings.ToLower(tool)
	if name == "apply_patch" {
		return toolCall{patch: firstString(input, "command", "patch", "input")}
	}
	if isShellTool(name) {
		return toolCall{shell: firstString(input, "command", "cmd")}
	}
	call := toolCall{path: firstString(input, "file_path", "path", "filePath", "target_file", "notebook_path", "file")}
	if call.path == "" {
		return toolCall{}
	}
	if strings.Contains(name, "delete") || strings.Contains(name, "remove") {
		call.kind = "delete"
		return call
	}
	if content, ok := firstPresent(input, "content", "contents", "file_text", "new_source", "text"); ok {
		call.kind = "write"
		call.content = content
		return call
	}
	if items, ok := input["edits"].([]any); ok {
		call.kind = "edit"
		call.replaces = true
		for _, item := range items {
			if fields, ok := item.(map[string]any); ok {
				call.edits = append(call.edits, textEditFrom(fields))
			}
		}
		return call
	}
	if _, hasOld := firstPresent(input, "old_string", "old_str"); hasOld {
		call.kind = "edit"
		call.replaces = true
		call.edits = []textEdit{textEditFrom(input)}
		return call
	}
	if newText, hasNew := firstPresent(input, "new_string", "new_str"); hasNew {
		call.kind = "edit"
		call.replaces = true
		call.edits = []textEdit{{new: newText}}
		return call
	}
	return toolCall{}
}

func textEditFrom(fields map[string]any) textEdit {
	all, _ := fields["replace_all"].(bool)
	return textEdit{old: firstString(fields, "old_string", "old_str"), new: firstString(fields, "new_string", "new_str"), all: all}
}

func isShellTool(name string) bool {
	for _, part := range []string{"bash", "shell", "pwsh", "powershell", "terminal", "exec"} {
		if strings.Contains(name, part) {
			return true
		}
	}
	return false
}

func firstString(input map[string]any, keys ...string) string {
	text, _ := firstPresent(input, keys...)
	return text
}

func firstPresent(input map[string]any, keys ...string) (string, bool) {
	for _, key := range keys {
		if text, ok := input[key].(string); ok {
			return text, true
		}
	}
	return "", false
}

// claudeTool answers Claude Code and Codex, which share this format. A clean edit gets no answer.
func claudeTool(askAsDeny bool) func(io.Writer, io.Writer, agentEvent, hook.Decision) int {
	return func(stdout, _ io.Writer, _ agentEvent, decision hook.Decision) int {
		output := map[string]any{"hookEventName": "PreToolUse"}
		switch decision.Action {
		case hook.Deny:
			output["permissionDecision"] = "deny"
		case hook.Ask:
			output["permissionDecision"] = "ask"
			if askAsDeny {
				output["permissionDecision"] = "deny"
			}
		default:
			if decision.Note == "" || askAsDeny {
				return 0
			}
			output["additionalContext"] = decision.Note
			writeJSON(stdout, map[string]any{"hookSpecificOutput": output})
			return 0
		}
		output["permissionDecisionReason"] = decision.Reason
		if decision.Note != "" && !askAsDeny {
			output["additionalContext"] = decision.Note
		}
		writeJSON(stdout, map[string]any{"hookSpecificOutput": output})
		return 0
	}
}

const stopPrompt = "ipso: the working tree violates decisions in force. Fix these, or use the decisions.propose tool to change a decision.\n"

// claudeStop gives violations back once. On the next stop the agent is already continuing because
// of this hook, so it reports and lets the session end, and the two cannot loop.
func claudeStop(stdout, _ io.Writer, event agentEvent, violations, notes []string) int {
	switch {
	case len(violations) == 0 && len(notes) == 0:
	case len(violations) == 0:
		writeJSON(stdout, map[string]any{"systemMessage": "ipso: " + strings.Join(notes, "\n")})
	case event.stopActive:
		writeJSON(stdout, map[string]any{"systemMessage": "ipso: violations remain and CI will report them.\n" + strings.Join(violations, "\n")})
	default:
		writeJSON(stdout, map[string]any{"decision": "block", "reason": stopPrompt + strings.Join(append(violations, notes...), "\n")})
	}
	return 0
}

func claudeSession(stdout io.Writer, text string) int {
	if text != "" {
		writeJSON(stdout, map[string]any{"hookSpecificOutput": map[string]any{"hookEventName": "SessionStart", "additionalContext": text}})
	}
	return 0
}

func copilotTool(stdout, _ io.Writer, _ agentEvent, decision hook.Decision) int {
	switch decision.Action {
	case hook.Deny:
		writeJSON(stdout, map[string]any{"permissionDecision": "deny", "permissionDecisionReason": decision.Reason})
	case hook.Ask:
		writeJSON(stdout, map[string]any{"permissionDecision": "ask", "permissionDecisionReason": decision.Reason})
	}
	return 0
}

// copilotStop has no field for a message that does not block, so what is left goes to stderr.
func copilotStop(stdout, stderr io.Writer, event agentEvent, violations, notes []string) int {
	if len(violations) > 0 && !event.stopActive {
		writeJSON(stdout, map[string]any{"decision": "block", "reason": stopPrompt + strings.Join(append(violations, notes...), "\n")})
		return 0
	}
	if len(violations)+len(notes) > 0 {
		fprintln(stderr, "ipso: "+strings.Join(append(violations, notes...), "\n"))
	}
	return 0
}

func copilotSession(stdout io.Writer, text string) int {
	if text != "" {
		writeJSON(stdout, map[string]any{"additionalContext": text})
	}
	return 0
}

// cursorTool answers with JSON every time, because Cursor treats a permission hook's invalid output
// as a refusal. preToolUse accepts ask and does not enforce it, so there ask becomes deny.
func cursorTool(stdout, _ io.Writer, event agentEvent, decision hook.Decision) int {
	permission := ""
	switch decision.Action {
	case hook.Deny:
		permission = "deny"
	case hook.Ask:
		permission = "deny"
		if event.name == "beforeshellexecution" {
			permission = "ask"
		}
	}
	if permission == "" {
		writeJSON(stdout, map[string]any{})
		return 0
	}
	writeJSON(stdout, map[string]any{"permission": permission, "user_message": decision.Reason, "agent_message": decision.Reason})
	return 0
}

// cursorStop sends the violations as the next message once. loop_count says it already did.
func cursorStop(stdout, _ io.Writer, event agentEvent, violations, notes []string) int {
	if len(violations) > 0 && !event.stopActive {
		writeJSON(stdout, map[string]any{"followup_message": stopPrompt + strings.Join(append(violations, notes...), "\n")})
		return 0
	}
	writeJSON(stdout, map[string]any{})
	return 0
}

func cursorSession(stdout io.Writer, text string) int {
	if text == "" {
		writeJSON(stdout, map[string]any{})
		return 0
	}
	writeJSON(stdout, map[string]any{"additional_context": text})
	return 0
}

// kiroTool refuses through exit 2 with the reason on stderr, the only refusal Kiro documents. It has
// no way to ask a person, so ask becomes a refusal.
func kiroTool(_, stderr io.Writer, _ agentEvent, decision hook.Decision) int {
	if decision.Action == hook.None {
		return 0
	}
	fprintln(stderr, decision.Reason)
	return 2
}

// kiroStop can only flag. Its documentation gives a stop hook no way to send the agent back.
func kiroStop(stdout, _ io.Writer, _ agentEvent, violations, notes []string) int {
	if len(violations)+len(notes) > 0 {
		fprintln(stdout, "ipso: "+strings.Join(append(violations, notes...), "\n"))
	}
	return 0
}

func kiroSession(stdout io.Writer, text string) int {
	if text != "" {
		fprintln(stdout, text)
	}
	return 0
}
