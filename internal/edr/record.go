package edr

import (
	"fmt"
	"math"
	"path"
	"slices"
	"strings"
	"time"
)

// Check is one object from the checks array.
type Check struct {
	Engine string
	Target string
	Ref    string
	Job    string
	Mode   string
}

// ScopeItem is one object from the scope array.
// An empty Env means the item applies in every environment.
// An empty Paths means the item applies to the whole repository.
type ScopeItem struct {
	Org   string
	Repo  string
	Env   []string
	Paths []string
}

// Waiver is one object from the waivers array.
type Waiver struct {
	Approver  string
	ValidFrom time.Time
	ValidTo   time.Time
}

// Premise is one object from the premises array.
// HasEquals is set when the probe uses equals, including when that value is null.
// Semver is set when the probe uses a semver constraint. Exactly one is set.
type Premise struct {
	ID        string
	Statement string
	Every     int
	URL       string
	Pointer   string
	Equals    any
	HasEquals bool
	Semver    string
}

// Record is the frontmatter a compiler needs from a validated document.
type Record struct {
	ID          string
	Slug        string
	Status      string
	Criticality string
	ValidFrom   time.Time
	ValidTo     *time.Time
	Scope       []ScopeItem
	Tags        []string
	Checks      []Check
	Waivers     []Waiver
	Premises    []Premise
}

// RecordFrom decodes a document that has already passed validation.
func RecordFrom(doc Document) (Record, error) {
	var rec Record
	var err error
	if rec.ID, err = requireString(doc.Front, "id"); err != nil {
		return Record{}, err
	}
	if rec.Slug, err = requireString(doc.Front, "slug"); err != nil {
		return Record{}, err
	}
	if rec.Status, err = requireString(doc.Front, "status"); err != nil {
		return Record{}, err
	}
	if rec.Criticality, err = requireString(doc.Front, "criticality"); err != nil {
		return Record{}, err
	}
	from, err := requireString(doc.Front, "valid_from")
	if err != nil {
		return Record{}, err
	}
	rec.ValidFrom, err = parseDate("valid_from", from)
	if err != nil {
		return Record{}, err
	}
	rawTo, ok := doc.Front["valid_to"]
	if !ok {
		return Record{}, fmt.Errorf("valid_to: missing")
	}
	if rawTo != nil {
		text, ok := rawTo.(string)
		if !ok {
			return Record{}, fmt.Errorf("valid_to: not a date")
		}
		parsed, err := parseDate("valid_to", text)
		if err != nil {
			return Record{}, err
		}
		rec.ValidTo = &parsed
	}
	rec.Scope, err = scopeFrom(doc.Front["scope"])
	if err != nil {
		return Record{}, err
	}
	rec.Tags, err = stringList(doc.Front["tags"])
	if err != nil {
		return Record{}, fmt.Errorf("tags: %w", err)
	}
	rec.Checks, err = checksFrom(doc.Front["checks"])
	if err != nil {
		return Record{}, err
	}
	rec.Waivers, err = waiversFrom(doc.Front["waivers"])
	if err != nil {
		return Record{}, err
	}
	rec.Premises, err = premisesFrom(doc.Front["premises"])
	if err != nil {
		return Record{}, err
	}
	return rec, nil
}

// WaiverInForce reports whether the waiver binds on the calendar date of now.
// The interval is half-open, like a record: valid_from is included and valid_to is excluded.
// A waiver whose valid_from is after valid_to never binds.
func (w Waiver) InForce(now time.Time) bool {
	today := calendarDate(now)
	return !today.Before(w.ValidFrom) && today.Before(w.ValidTo)
}

// InForce reports whether the record binds on the calendar date of now.
// The interval is half-open: valid_from is included and valid_to is excluded.
// A null valid_to does not end. The status must be accepted, verified, or needs-review.
// The date comes from now's location, so time.Now uses the local calendar day.
func (r Record) InForce(now time.Time) bool {
	switch r.Status {
	case "accepted", "verified", "needs-review":
	default:
		return false
	}
	today := calendarDate(now)
	if today.Before(r.ValidFrom) {
		return false
	}
	if r.ValidTo != nil && !today.Before(*r.ValidTo) {
		return false
	}
	return true
}

// Applies reports whether one scope item covers the selection. An omitted field matches every
// scope, which widens the answer, the rule of ADR-0051. repo is owner/name, compared without case.
func (r Record) Applies(repo string, paths []string, env string) bool {
	for _, item := range r.Scope {
		if item.covers(repo, paths, env) {
			return true
		}
	}
	return false
}

func (s ScopeItem) covers(repo string, paths []string, env string) bool {
	if repo != "" {
		owner, _, _ := strings.Cut(repo, "/")
		if s.Org != "" && !strings.EqualFold(s.Org, owner) {
			return false
		}
		if s.Repo != "" {
			if matched, err := path.Match(strings.ToLower(s.Repo), strings.ToLower(repo)); err != nil || !matched {
				return false
			}
		}
	}
	if env != "" && len(s.Env) > 0 && !slices.Contains(s.Env, env) {
		return false
	}
	if len(paths) == 0 || len(s.Paths) == 0 {
		return true
	}
	for _, name := range paths {
		for _, glob := range s.Paths {
			if MatchPath(glob, name) {
				return true
			}
		}
	}
	return false
}

// EffectiveMode returns the check mode, or the mode implied by criticality
// when the check omits one: blocking to block, warning to warn, advisory to advise.
func (c Check) EffectiveMode(criticality string) (string, error) {
	if c.Mode != "" {
		return c.Mode, nil
	}
	switch criticality {
	case "blocking":
		return "block", nil
	case "warning":
		return "warn", nil
	case "advisory":
		return "advise", nil
	default:
		return "", fmt.Errorf("criticality %q has no mode", criticality)
	}
}

func calendarDate(now time.Time) time.Time {
	year, month, day := now.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

func parseDate(key, text string) (time.Time, error) {
	parsed, err := time.Parse("2006-01-02", text)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", key, err)
	}
	return parsed, nil
}

func requireString(front map[string]any, key string) (string, error) {
	raw, ok := front[key]
	if !ok || raw == nil {
		return "", fmt.Errorf("%s: missing", key)
	}
	text, ok := raw.(string)
	if !ok || text == "" {
		return "", fmt.Errorf("%s: missing", key)
	}
	return text, nil
}

func scopeFrom(raw any) ([]ScopeItem, error) {
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("scope: not an array")
	}
	scope := make([]ScopeItem, 0, len(items))
	for i, item := range items {
		mapping, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("scope[%d]: not an object", i)
		}
		envs, err := stringList(mapping["env"])
		if err != nil {
			return nil, fmt.Errorf("scope[%d]: env: %w", i, err)
		}
		paths, err := stringList(mapping["paths"])
		if err != nil {
			return nil, fmt.Errorf("scope[%d]: paths: %w", i, err)
		}
		org, _ := mapping["org"].(string)
		repo, _ := mapping["repo"].(string)
		scope = append(scope, ScopeItem{Org: org, Repo: repo, Env: envs, Paths: paths})
	}
	return scope, nil
}

func waiversFrom(raw any) ([]Waiver, error) {
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("waivers: not an array")
	}
	waivers := make([]Waiver, 0, len(items))
	for i, item := range items {
		mapping, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("waivers[%d]: not an object", i)
		}
		waiver := Waiver{}
		var err error
		if waiver.Approver, err = requireString(mapping, "approver"); err != nil {
			return nil, fmt.Errorf("waivers[%d]: %w", i, err)
		}
		from, err := requireString(mapping, "valid_from")
		if err != nil {
			return nil, fmt.Errorf("waivers[%d]: %w", i, err)
		}
		if waiver.ValidFrom, err = parseDate("valid_from", from); err != nil {
			return nil, fmt.Errorf("waivers[%d]: %w", i, err)
		}
		to, err := requireString(mapping, "valid_to")
		if err != nil {
			return nil, fmt.Errorf("waivers[%d]: %w", i, err)
		}
		if waiver.ValidTo, err = parseDate("valid_to", to); err != nil {
			return nil, fmt.Errorf("waivers[%d]: %w", i, err)
		}
		waivers = append(waivers, waiver)
	}
	return waivers, nil
}

func stringList(raw any) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("not an array")
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok || text == "" {
			return nil, fmt.Errorf("not a string")
		}
		out = append(out, text)
	}
	return out, nil
}

func premisesFrom(raw any) ([]Premise, error) {
	if raw == nil {
		return nil, nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("premises: not an array")
	}
	out := make([]Premise, 0, len(items))
	for i, item := range items {
		mapping, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("premises[%d]: not an object", i)
		}
		premise := Premise{}
		var err error
		if premise.ID, err = requireString(mapping, "id"); err != nil {
			return nil, fmt.Errorf("premises[%d]: %w", i, err)
		}
		if premise.Statement, err = requireString(mapping, "statement"); err != nil {
			return nil, fmt.Errorf("premises[%d]: %w", i, err)
		}
		every, ok := wholeInt(mapping["every"])
		if !ok {
			return nil, fmt.Errorf("premises[%d]: every: not an integer", i)
		}
		premise.Every = every
		probe, ok := mapping["probe"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("premises[%d]: probe: not an object", i)
		}
		if premise.URL, err = requireString(probe, "url"); err != nil {
			return nil, fmt.Errorf("premises[%d]: probe: %w", i, err)
		}
		pointer, ok := probe["pointer"]
		if !ok || pointer == nil {
			return nil, fmt.Errorf("premises[%d]: probe: pointer: missing", i)
		}
		text, ok := pointer.(string)
		if !ok {
			return nil, fmt.Errorf("premises[%d]: probe: pointer: not a string", i)
		}
		premise.Pointer = text
		_, hasEquals := probe["equals"]
		_, hasSemver := probe["semver"]
		if hasEquals == hasSemver {
			return nil, fmt.Errorf("premises[%d]: probe: comparison", i)
		}
		if hasEquals {
			premise.HasEquals = true
			premise.Equals = probe["equals"]
		} else {
			semver, ok := probe["semver"].(string)
			if !ok || semver == "" {
				return nil, fmt.Errorf("premises[%d]: probe: semver: missing", i)
			}
			premise.Semver = semver
		}
		out = append(out, premise)
	}
	return out, nil
}

func wholeInt(raw any) (int, bool) {
	number, ok := raw.(float64)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) || number != math.Trunc(number) {
		return 0, false
	}
	if number < 1 || number > 365 {
		return 0, false
	}
	return int(number), true
}

func checksFrom(raw any) ([]Check, error) {
	if raw == nil {
		return []Check{}, nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("checks: not an array")
	}
	checks := make([]Check, 0, len(items))
	for i, item := range items {
		mapping, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("checks[%d]: not an object", i)
		}
		check := Check{}
		var err error
		if check.Engine, err = requireString(mapping, "engine"); err != nil {
			return nil, fmt.Errorf("checks[%d]: %w", i, err)
		}
		if check.Target, err = optionalString(mapping, "target"); err != nil {
			return nil, fmt.Errorf("checks[%d]: %w", i, err)
		}
		if check.Ref, err = optionalString(mapping, "ref"); err != nil {
			return nil, fmt.Errorf("checks[%d]: %w", i, err)
		}
		if check.Job, err = optionalString(mapping, "job"); err != nil {
			return nil, fmt.Errorf("checks[%d]: %w", i, err)
		}
		if check.Mode, err = optionalString(mapping, "mode"); err != nil {
			return nil, fmt.Errorf("checks[%d]: %w", i, err)
		}
		checks = append(checks, check)
	}
	return checks, nil
}

func optionalString(front map[string]any, key string) (string, error) {
	raw, ok := front[key]
	if !ok || raw == nil {
		return "", nil
	}
	text, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s: not a string", key)
	}
	return text, nil
}
