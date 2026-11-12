package edr

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	ulidPattern        = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	slugPattern        = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	renderOwnerPattern = regexp.MustCompile(`^team:[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
	renderDatePattern  = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$`)
)

// renderedRecord is the frontmatter of a rendered file, in file order.
type renderedRecord struct {
	EDR         int      `yaml:"edr"`
	ID          string   `yaml:"id"`
	Slug        string   `yaml:"slug"`
	Title       string   `yaml:"title"`
	Status      string   `yaml:"status"`
	Owner       string   `yaml:"owner"`
	Scope       []any    `yaml:"scope"`
	ValidFrom   string   `yaml:"valid_from"`
	ValidTo     *string  `yaml:"valid_to"`
	ReviewBy    string   `yaml:"review_by"`
	Supersedes  []string `yaml:"supersedes"`
	Criticality string   `yaml:"criticality"`
	Checks      []any    `yaml:"checks"`
	Waivers     []any    `yaml:"waivers"`
	Sources     []any    `yaml:"sources"`
	Tags        []string `yaml:"tags"`
	Premises    []any    `yaml:"premises,omitempty"`
	Inferred    bool     `yaml:"inferred,omitempty"`
}

// RenderDecision renders one stored decision version as a valid EDR file. The body is the JSON object a
// registry holds, which may lack any field, and all of it is untrusted. valid_from and valid_to come from
// the valid time of the version, not from the body. A field of the body is used when the schema accepts it
// and replaced by a default otherwise, and a default sets inferred. The result always passes Validate.
// Only an id that is not a ULID, or a zero valid_from, is an error.
func RenderDecision(id string, body []byte, validFrom time.Time, validTo *time.Time) (string, error) {
	if !ulidPattern.MatchString(id) {
		return "", fmt.Errorf("the id is not a ULID")
	}
	if validFrom.IsZero() {
		return "", fmt.Errorf("valid_from is required")
	}
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		fields = nil
	}
	from := renderDate(validFrom)
	var to *string
	if validTo != nil {
		end := renderDate(*validTo)
		to = &end
	}
	text := tryRender(fromBody(id, fields, from, to), fields)
	if text == "" {
		text = tryRender(defaults(id, from, to, fields), fields)
	}
	if text == "" {
		return "", fmt.Errorf("the decision cannot be rendered")
	}
	return text, nil
}

// renderDate prints the calendar day of t in UTC. A year the schema cannot hold, which PostgreSQL allows, is
// held to 0001-01-01 or 9999-12-31, so a far bound never stops the export.
func renderDate(t time.Time) string {
	t = t.UTC()
	switch {
	case t.Year() < 1:
		return "0001-01-01"
	case t.Year() > 9999:
		return "9999-12-31"
	}
	return t.Format("2006-01-02")
}

func tryRender(rec renderedRecord, fields map[string]any) string {
	text, err := encode(rec, renderBody(rec.Title, fields))
	if err != nil {
		return ""
	}
	doc, err := Parse(text)
	if err != nil || len(Validate(doc)) > 0 {
		return ""
	}
	return text
}

// reviewBy is a year after the start, or the start itself when that year is out of range.
func reviewBy(from string) string {
	if next := addYears(from, 1); renderDatePattern.MatchString(next) {
		return next
	}
	return from
}

func defaults(id, from string, to *string, fields map[string]any) renderedRecord {
	title := cleanTitle(fields["title"])
	if title == "" {
		title = "Untitled decision"
	}
	return renderedRecord{
		EDR: 1, ID: id, Slug: "decision-" + strings.ToLower(id[20:]), Title: title,
		Status: "accepted", Owner: "team:unknown", Scope: []any{map[string]any{"org": "unknown"}},
		ValidFrom: from, ValidTo: to, ReviewBy: reviewBy(from), Supersedes: []string{},
		Criticality: "advisory", Checks: []any{}, Waivers: []any{},
		Sources:  []any{map[string]any{"type": "registry", "url": "https://example.invalid/registry/" + strings.ToLower(id)}},
		Tags:     []string{},
		Inferred: true,
	}
}

// fromBody takes each field of the body that has the right shape. Whether the values satisfy the schema is
// checked on the whole file by the caller.
func fromBody(id string, fields map[string]any, from string, to *string) renderedRecord {
	rec := defaults(id, from, to, fields)
	rec.Inferred = false
	used := func(ok bool) {
		if !ok {
			rec.Inferred = true
		}
	}
	if s, ok := fields["slug"].(string); ok && slugPattern.MatchString(s) {
		rec.Slug = s
	} else {
		used(false)
	}
	used(cleanTitle(fields["title"]) != "")
	if s, ok := fields["status"].(string); ok && s != "" {
		rec.Status = s
	} else {
		used(false)
	}
	if s, ok := fields["owner"].(string); ok && renderOwnerPattern.MatchString(s) {
		rec.Owner = s
	} else {
		used(false)
	}
	if s, ok := fields["criticality"].(string); ok && s != "" {
		rec.Criticality = s
	} else {
		used(false)
	}
	if s, ok := fields["review_by"].(string); ok && renderDatePattern.MatchString(s) {
		rec.ReviewBy = s
	}
	if l, ok := fields["scope"].([]any); ok && len(l) > 0 {
		rec.Scope = l
	} else {
		used(false)
	}
	if l, ok := fields["sources"].([]any); ok && len(l) > 0 {
		rec.Sources = l
	} else {
		used(false)
	}
	rec.Supersedes = stringsOf(fields["supersedes"], rec.Supersedes)
	rec.Tags = stringsOf(fields["tags"], rec.Tags)
	if l, ok := fields["checks"].([]any); ok {
		rec.Checks = l
	}
	if l, ok := fields["waivers"].([]any); ok {
		rec.Waivers = l
	}
	if l, ok := fields["premises"].([]any); ok && len(l) > 0 {
		rec.Premises = l
	}
	return rec
}

func stringsOf(raw any, fallback []string) []string {
	items, ok := raw.([]any)
	if !ok {
		return fallback
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return fallback
		}
		out = append(out, s)
	}
	return out
}

// cleanTitle returns the title on one line, or an empty string when there is none.
func cleanTitle(raw any) string {
	s, _ := raw.(string)
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

func renderBody(title string, fields map[string]any) string {
	pick := func(missing string, keys ...string) string {
		for _, key := range keys {
			if s, ok := fields[key].(string); ok {
				if text := safeSection(s); text != "" {
					return text
				}
			}
		}
		return missing
	}
	return buildBody(title, map[string]string{
		"context":      pick("The registry holds no context for this decision.", "context"),
		"decision":     pick("The registry holds no statement for this decision.", "decision", "statement"),
		"alternatives": pick("The registry holds no alternatives for this decision.", "alternatives"),
		"consequences": pick("The registry holds no consequences for this decision.", "consequences"),
		"verification": pick("The registry holds no verification for this decision.", "verification"),
	})
}

// safeSection keeps stored text from adding a heading or hiding in a terminal: a line that starts with #
// gets a backslash, and a control character other than a tab becomes a space.
func safeSection(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		line = strings.Map(func(r rune) rune {
			if (r < 0x20 && r != '\t') || r == 0x7f || r == 0x2028 || r == 0x2029 {
				return ' '
			}
			return r
		}, line)
		if strings.HasPrefix(strings.TrimLeft(line, " "), "#") {
			line = `\` + strings.TrimLeft(line, " ")
		}
		lines[i] = line
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}
