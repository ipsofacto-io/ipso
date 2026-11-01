package edr

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Import turns one MADR or Nygard ADR into an EDR document.
// A new id is not in the source, so the result sets inferred to true.
func Import(filename, text string, now time.Time) (string, error) {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	title, ok := headingTitle(text)
	if !ok {
		return "", fmt.Errorf("no level-1 heading")
	}
	sections := sectionBodies(text)
	status, statusKnown := readStatus(text, sections["status"])
	validFrom, dateKnown := readDate(text)
	if !dateKnown {
		validFrom = now.UTC().Format("2006-01-02")
	}
	owner, ownerKnown := readOwner(text)
	if !ownerKnown {
		owner = "team:unknown"
	}
	slug := slugFrom(filename, title)
	var validTo *string
	if status == "superseded" {
		end := validFrom
		validTo = &end
	}
	reviewBy := addYears(validFrom, 1)
	sourceURL := firstHTTPS(text)
	if sourceURL == "" {
		sourceURL = "https://example.invalid/adr/" + slug
	}
	rec := importedRecord{
		EDR:         1,
		ID:          newULID(now),
		Slug:        slug,
		Title:       title,
		Status:      status,
		Owner:       owner,
		Scope:       []scopeItem{{Org: "unknown"}},
		ValidFrom:   validFrom,
		ValidTo:     validTo,
		ReviewBy:    reviewBy,
		Supersedes:  []string{},
		Criticality: "warning",
		Checks:      []any{},
		Waivers:     []any{},
		Sources:     []sourceItem{{Type: "adr", URL: sourceURL}},
		Tags:        []string{},
		Inferred:    true,
	}
	if !statusKnown || !dateKnown || !ownerKnown || sourceURL == "" {
		rec.Inferred = true
	}
	body := buildBody(title, sections)
	return encode(rec, body)
}

type importedRecord struct {
	EDR         int          `yaml:"edr"`
	ID          string       `yaml:"id"`
	Slug        string       `yaml:"slug"`
	Title       string       `yaml:"title"`
	Status      string       `yaml:"status"`
	Owner       string       `yaml:"owner"`
	Scope       []scopeItem  `yaml:"scope"`
	ValidFrom   string       `yaml:"valid_from"`
	ValidTo     *string      `yaml:"valid_to"`
	ReviewBy    string       `yaml:"review_by"`
	Supersedes  []string     `yaml:"supersedes"`
	Criticality string       `yaml:"criticality"`
	Checks      []any        `yaml:"checks"`
	Waivers     []any        `yaml:"waivers"`
	Sources     []sourceItem `yaml:"sources"`
	Tags        []string     `yaml:"tags"`
	Inferred    bool         `yaml:"inferred"`
}

type scopeItem struct {
	Org   string   `yaml:"org,omitempty"`
	Paths []string `yaml:"paths,omitempty"`
	Env   []string `yaml:"env,omitempty"`
}

type sourceItem struct {
	Type string `yaml:"type"`
	URL  string `yaml:"url"`
}

func encode(rec importedRecord, body string) (string, error) {
	var buf bytes.Buffer
	buf.WriteString("---\n")
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(rec); err != nil {
		return "", err
	}
	if err := encoder.Close(); err != nil {
		return "", err
	}
	buf.WriteString("---\n")
	buf.WriteString(body)
	if !strings.HasSuffix(buf.String(), "\n") {
		buf.WriteByte('\n')
	}
	return buf.String(), nil
}

func buildBody(title string, sections map[string]string) string {
	context := firstNonEmpty(sections["context"], "The source file did not describe context.")
	decision := firstNonEmpty(sections["decision"], "The source file did not state a decision.")
	alternatives := firstNonEmpty(sections["alternatives"], "The source file did not list alternatives.")
	consequences := firstNonEmpty(sections["consequences"], "The source file did not list consequences.")
	verification := firstNonEmpty(sections["verification"], "The source file did not describe verification.")
	var buf strings.Builder
	fmt.Fprintf(&buf, "# %s\n\n", title)
	fmt.Fprintf(&buf, "## Context\n\n%s\n\n", strings.TrimSpace(context))
	fmt.Fprintf(&buf, "## Decision\n\n%s\n\n", strings.TrimSpace(decision))
	fmt.Fprintf(&buf, "## Alternatives considered\n\n%s\n\n", strings.TrimSpace(alternatives))
	fmt.Fprintf(&buf, "## Consequences\n\n%s\n\n", strings.TrimSpace(consequences))
	fmt.Fprintf(&buf, "## Verification\n\n%s\n", strings.TrimSpace(verification))
	return buf.String()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func headingTitle(text string) (string, bool) {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "# ") && !strings.HasPrefix(line, "## ") {
			title := strings.TrimSpace(strings.TrimPrefix(line, "# "))
			title = stripTitleNoise(title)
			if title == "" {
				return "", false
			}
			return title, true
		}
	}
	return "", false
}

var (
	numberedTitle = regexp.MustCompile(`^(?:ADR[ -]\d+[:.]?\s+|\d+[.)]\s+)`)
	bracketTitle  = regexp.MustCompile(`^\[(.*)\]$`)
)

func stripTitleNoise(title string) string {
	title = strings.TrimSpace(title)
	title = numberedTitle.ReplaceAllString(title, "")
	if parts := bracketTitle.FindStringSubmatch(title); parts != nil {
		title = parts[1]
	}
	return strings.TrimSpace(title)
}

func sectionBodies(text string) map[string]string {
	lines := strings.Split(text, "\n")
	out := map[string]string{}
	name := ""
	var buf []string
	flush := func() {
		if name == "" {
			return
		}
		body := strings.TrimSpace(strings.Join(buf, "\n"))
		if body == "" {
			return
		}
		if existing := out[name]; existing != "" {
			out[name] = existing + "\n\n" + body
			return
		}
		out[name] = body
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "## ") && !strings.HasPrefix(line, "### ") {
			flush()
			name = canonicalSection(strings.TrimSpace(strings.TrimPrefix(line, "## ")))
			buf = nil
			continue
		}
		if name != "" {
			buf = append(buf, line)
		}
	}
	flush()
	return out
}

func canonicalSection(heading string) string {
	switch strings.ToLower(heading) {
	case "context", "context and problem statement":
		return "context"
	case "decision", "decision outcome":
		return "decision"
	case "consequences":
		return "consequences"
	case "considered options", "pros and cons of the options", "alternatives considered":
		return "alternatives"
	case "verification":
		return "verification"
	case "status":
		return "status"
	case "decision drivers":
		return "context"
	default:
		return ""
	}
}

func readStatus(text, statusSection string) (string, bool) {
	candidates := []string{statusSection}
	for _, line := range strings.Split(text, "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "status:") || strings.HasPrefix(lower, "* status:") {
			candidates = append(candidates, lower)
		}
	}
	for _, candidate := range candidates {
		if status, ok := mapStatus(candidate); ok {
			return status, true
		}
	}
	return "proposed", false
}

func mapStatus(text string) (string, bool) {
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "supersed"), strings.Contains(lower, "superced"):
		return "superseded", true
	case strings.Contains(lower, "rejected"), strings.Contains(lower, "declined"):
		return "rejected", true
	case strings.Contains(lower, "deprecated"):
		return "deprecated", true
	case strings.Contains(lower, "needs-review"), strings.Contains(lower, "needs review"):
		return "needs-review", true
	case strings.Contains(lower, "proposed"), strings.Contains(lower, "pending"):
		return "proposed", true
	case strings.Contains(lower, "accepted"), strings.Contains(lower, "approved"):
		return "accepted", true
	default:
		return "", false
	}
}

var datePattern = regexp.MustCompile(`\b(\d{4}-\d{2}-\d{2})\b`)

func readDate(text string) (string, bool) {
	match := datePattern.FindStringSubmatch(text)
	if match == nil {
		return "", false
	}
	return match[1], true
}

var ownerPattern = regexp.MustCompile(`team:[a-z][a-z0-9]*(?:-[a-z0-9]+)*`)

func readOwner(text string) (string, bool) {
	if match := ownerPattern.FindString(text); match != "" {
		return match, true
	}
	return "", false
}

var httpsPattern = regexp.MustCompile(`https://[^\s)>\]]+`)

func firstHTTPS(text string) string {
	match := httpsPattern.FindString(text)
	return strings.TrimRight(match, ".,;")
}

var slugClean = regexp.MustCompile(`[^a-z0-9]+`)

func slugFrom(filename, title string) string {
	base := strings.TrimSuffix(filename, ".md")
	base = strings.ToLower(base)
	base = regexp.MustCompile(`^(?:adr-?)?\d+-`).ReplaceAllString(base, "")
	slug := cleanSlug(base)
	if slug == "" {
		slug = cleanSlug(title)
	}
	if slug == "" {
		return "decision"
	}
	return slug
}

func cleanSlug(value string) string {
	value = strings.ToLower(value)
	value = slugClean.ReplaceAllString(value, "-")
	return strings.Trim(value, "-")
}

func addYears(date string, years int) string {
	parsed, err := time.Parse("2006-01-02", date)
	if err != nil {
		return date
	}
	return parsed.AddDate(years, 0, 0).Format("2006-01-02")
}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

func newULID(now time.Time) string {
	var raw [16]byte
	ms := uint64(now.UTC().UnixMilli())
	raw[0] = byte(ms >> 40)
	raw[1] = byte(ms >> 32)
	raw[2] = byte(ms >> 24)
	raw[3] = byte(ms >> 16)
	raw[4] = byte(ms >> 8)
	raw[5] = byte(ms)
	if _, err := rand.Read(raw[6:]); err != nil {
		copy(raw[6:], []byte("ipsoproba"))
	}
	var number big.Int
	number.SetBytes(raw[:])
	out := make([]byte, 26)
	mask := big.NewInt(31)
	part := new(big.Int)
	for i := 25; i >= 0; i-- {
		part.And(&number, mask)
		out[i] = crockford[part.Uint64()]
		number.Rsh(&number, 5)
	}
	return string(out)
}
