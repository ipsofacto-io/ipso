package edr

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	maxProposalTitle = 200
	maxProposalText  = 8000
	// ProposalTag marks a record an agent proposed.
	ProposalTag = "agent-proposal"
)

// ProposalInput is what an agent states about a new decision. All of it is untrusted text.
type ProposalInput struct {
	Title        string
	Statement    string
	Rationale    string
	Verification string
	Paths        []string
	Env          []string
	SessionRef   string
}

// NewProposal renders a valid EDR file with status proposed and returns its id, slug, and text. No
// input reaches the status, the owner, the checks, or the waivers, so a proposal cannot put itself
// in force. Input that would break a heading, or that does not validate, is an error.
func NewProposal(in ProposalInput, now time.Time) (string, string, string, error) {
	title := strings.TrimSpace(in.Title)
	if title == "" || len(title) > maxProposalTitle || strings.ContainsFunc(title, isControl) {
		return "", "", "", fmt.Errorf("title must be 1 to %d characters on one line", maxProposalTitle)
	}
	for name, text := range map[string]string{"statement": in.Statement, "rationale": in.Rationale, "verification": in.Verification, "session_ref": in.SessionRef} {
		if err := checkProposalText(name, text); err != nil {
			return "", "", "", err
		}
	}
	if strings.TrimSpace(in.Statement) == "" {
		return "", "", "", fmt.Errorf("statement is required")
	}
	if strings.TrimSpace(in.Rationale) == "" {
		return "", "", "", fmt.Errorf("rationale is required")
	}
	id := newULID(now)
	base := cleanSlug(strings.ToLower(title))
	if base == "" {
		base = "proposal"
	}
	slug := base + "-" + strings.ToLower(id[len(id)-6:])

	sourceURL := "https://example.invalid/agent-session/" + strings.ToLower(id)
	if parsed, err := url.Parse(in.SessionRef); err == nil && parsed.Scheme == "https" && parsed.Host != "" && !strings.ContainsAny(in.SessionRef, " \t\n") {
		sourceURL = in.SessionRef
	}
	context := strings.TrimSpace(in.Rationale)
	if ref := strings.TrimSpace(in.SessionRef); ref != "" {
		context += "\n\nProposed by an AI coding agent in session `" + strings.ReplaceAll(ref, "`", "'") + "`."
	} else {
		context += "\n\nProposed by an AI coding agent."
	}
	date := now.UTC().Format("2006-01-02")
	item := scopeItem{Paths: in.Paths, Env: in.Env}
	if len(in.Paths) == 0 && len(in.Env) == 0 {
		item.Org = "unknown"
	}
	rec := importedRecord{
		EDR:         1,
		ID:          id,
		Slug:        slug,
		Title:       title,
		Status:      "proposed",
		Owner:       "team:unknown",
		Scope:       []scopeItem{item},
		ValidFrom:   date,
		ReviewBy:    addYears(date, 1),
		Supersedes:  []string{},
		Criticality: "advisory",
		Checks:      []any{},
		Waivers:     []any{},
		Sources:     []sourceItem{{Type: "agent-session", URL: sourceURL}},
		Tags:        []string{ProposalTag},
		Inferred:    true,
	}
	body := buildBody(title, map[string]string{
		"context":      context,
		"decision":     in.Statement,
		"alternatives": "The proposing agent did not list alternatives. The reviewer should.",
		"consequences": "The proposing agent did not list consequences. The reviewer should.",
		"verification": firstNonEmpty(strings.TrimSpace(in.Verification), "The proposing agent did not describe verification."),
	})
	text, err := encode(rec, body)
	if err != nil {
		return "", "", "", err
	}
	doc, err := Parse(text)
	if err != nil {
		return "", "", "", err
	}
	if problems := Validate(doc); len(problems) > 0 {
		return "", "", "", fmt.Errorf("the proposal is not valid: %s", strings.Join(problems, "; "))
	}
	return id, slug, text, nil
}

func isControl(r rune) bool {
	return r < 0x20 || r == 0x7f
}

// checkProposalText refuses text that could add a heading to the record or hide in a terminal.
func checkProposalText(name, text string) error {
	if len(text) > maxProposalText {
		return fmt.Errorf("%s is longer than %d bytes", name, maxProposalText)
	}
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, "#") {
			return fmt.Errorf("%s has a line that starts a heading", name)
		}
		if strings.ContainsFunc(line, func(r rune) bool { return isControl(r) && r != '\t' }) {
			return fmt.Errorf("%s has a control character", name)
		}
	}
	return nil
}
