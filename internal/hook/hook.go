// Package hook decides what an agent hook answers. An agent's adapter turns its event into a
// proposed edit, and this package turns the verdicts into one decision (ADR-0074). It holds no
// agent format, so every adapter gets the same answer for the same edit.
package hook

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/edit"
	"github.com/ipsofacto-io/ipso/internal/edr"
)

// Action is what the agent should do. The order is from least to most restrictive.
type Action int

const (
	// None gives no opinion. The agent's own permission flow continues. A hook never says allow,
	// because that would approve an edit the person's own rules might stop.
	None Action = iota
	// Ask stops for a person.
	Ask
	// Deny refuses the edit.
	Deny
)

// Decision is the answer to one proposed edit. Reason is safe to show the agent.
type Decision struct {
	Action Action
	Reason string
	// Note is advice that does not stop the edit, for a check in advise mode.
	Note string
}

// ipsoDirWord finds the directory name as a word, so `rm -rf .ipso` counts and `.ipsofile` does not.
var ipsoDirWord = regexp.MustCompile(`(?i)(^|[^A-Za-z0-9_.-])\.ipso($|[^A-Za-z0-9_-])`)

// Protection is what the hook guards around the checks themselves. A person changes these, because
// an agent that edits a decision or a build could remove what stops it.
type Protection struct {
	DecisionGlobs []string
}

// Protected reports whether a path is a decision file or part of the ipso directory.
func (p Protection) Protected(name string) bool {
	// A case-insensitive file system opens .IPSO as .ipso.
	first, _, _ := strings.Cut(name, "/")
	if strings.EqualFold(first, ".ipso") {
		return true
	}
	for _, glob := range p.DecisionGlobs {
		if edr.MatchPath(glob, name) {
			return true
		}
	}
	return false
}

// CommandTouchesProtected is a plain text search of a shell command. It catches an agent that
// writes the build or a decision directly. It is not a sandbox, and a command can hide a path.
func (p Protection) CommandTouchesProtected(command string) bool {
	if ipsoDirWord.MatchString(command) {
		return true
	}
	for _, glob := range p.DecisionGlobs {
		literal, _, _ := strings.Cut(glob, "*")
		if literal != "" && strings.Contains(command, literal) {
			return true
		}
	}
	return false
}

// ProtectedReason is the reason for an edit Protected or CommandTouchesProtected caught.
const ProtectedReason = "ipso: this changes a decision record or the compiled checks, and a person makes that change. To change a decision, use the decisions.propose tool."

// Evaluate returns the most restrictive decision of every check that covers the proposals. A check
// that cannot evaluate asks a person, because silence would read as a pass and a refusal would stop
// all work over a problem the agent cannot fix.
func Evaluate(build compiler.Build, proposals []edit.Proposal, now time.Time) (Decision, error) {
	results, err := edit.Evaluate(build, proposals, "", now)
	if err != nil {
		return Decision{}, err
	}
	decision := Decision{}
	var denied, asked, noted []string
	for _, result := range results {
		verdict, _ := compiler.Judge(result.Entry, result.Outcome)
		switch {
		case verdict.Result == "error":
			asked = append(asked, fmt.Sprintf("%s could not evaluate: %s", label(result.Entry), compiler.EscapeControls(result.Outcome.Err.Error())))
		case verdict.Result != "fail":
		default:
			text := describe(result)
			switch result.Entry.Mode {
			case "block":
				denied = append(denied, text)
			case "warn":
				asked = append(asked, text)
			default:
				noted = append(noted, text)
			}
		}
	}
	switch {
	case len(denied) > 0:
		decision.Action = Deny
		decision.Reason = "ipso: this edit violates a decision in force.\n" + strings.Join(append(denied, asked...), "\n") + "\nTo change a decision, use the decisions.propose tool."
	case len(asked) > 0:
		decision.Action = Ask
		decision.Reason = "ipso: a person should look at this edit.\n" + strings.Join(asked, "\n")
	}
	if len(noted) > 0 {
		decision.Note = "ipso advice:\n" + strings.Join(noted, "\n")
	}
	return decision, nil
}

// label names a check and links its decision by record path. A checkout has that path and no URL.
func label(entry compiler.Entry) string {
	name := entry.Slug
	if entry.Title != "" {
		name = entry.Title + " (" + entry.Slug + ")"
	}
	text := compiler.EscapeControls(name)
	if entry.Path != "" {
		text += ", decision " + compiler.EscapeControls(entry.Path)
	}
	return text
}

func describe(result edit.Result) string {
	messages := make([]string, 0, len(result.Outcome.Violations))
	for _, violation := range result.Outcome.Violations {
		if violation.Baselined {
			continue
		}
		message := compiler.EscapeControls(violation.Message)
		if violation.Address != "" {
			message = compiler.EscapeControls(violation.Address) + ": " + message
		}
		messages = append(messages, message)
	}
	return "- " + label(result.Entry) + ": " + strings.Join(messages, "; ")
}
