// Package sarif encodes check outcomes as one SARIF 2.1.0 run for GitHub code scanning.
//
// A SARIF file leaves the runner, so every message is written here. Engine text, plan values,
// resource addresses, waiver approvers, and error text never reach the output.
package sarif

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

const (
	schemaURI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	srcRoot   = "%SRCROOT%"

	// maxResults is the number of results GitHub displays for one run.
	maxResults = 5000

	maxNameRunes        = 255
	maxDescriptionRunes = 1024

	decisionLocationID = 1
	genericErrorCode   = "evaluation-error"

	levelError   = "error"
	levelWarning = "warning"
	levelNote    = "note"
)

// safeToken is the form of a reason code and of a slug that is safe in a code span.
var safeToken = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Check is one evaluated manifest entry.
type Check struct {
	Entry   compiler.Entry
	Outcome compiler.Outcome
}

type log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool              tool              `json:"tool"`
	AutomationDetails automationDetails `json:"automationDetails"`
	Invocations       []invocation      `json:"invocations"`
	Results           []result          `json:"results"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
	Rules          []rule `json:"rules"`
}

type automationDetails struct {
	ID string `json:"id"`
}

type invocation struct {
	ExecutionSuccessful        bool           `json:"executionSuccessful"`
	ToolExecutionNotifications []notification `json:"toolExecutionNotifications,omitempty"`
}

type notification struct {
	Level   string  `json:"level"`
	Message message `json:"message"`
}

type rule struct {
	ID                   string               `json:"id"`
	Name                 string               `json:"name"`
	ShortDescription     message              `json:"shortDescription"`
	FullDescription      message              `json:"fullDescription"`
	Help                 help                 `json:"help"`
	DefaultConfiguration defaultConfiguration `json:"defaultConfiguration"`
	Properties           ruleProperties       `json:"properties"`
}

type help struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

type defaultConfiguration struct {
	Level string `json:"level"`
}

type ruleProperties struct {
	Tags []string `json:"tags"`
}

type message struct {
	Text string `json:"text"`
}

type result struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             message           `json:"message"`
	Locations           []location        `json:"locations"`
	RelatedLocations    []relatedLocation `json:"relatedLocations"`
	PartialFingerprints fingerprints      `json:"partialFingerprints"`
	Suppressions        []suppression     `json:"suppressions,omitempty"`
}

type fingerprints struct {
	PrimaryLocationLineHash string `json:"primaryLocationLineHash"`
}

type suppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type relatedLocation struct {
	ID               int              `json:"id"`
	PhysicalLocation physicalLocation `json:"physicalLocation"`
	Message          message          `json:"message"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           region           `json:"region"`
}

type artifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type region struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine"`
	EndColumn   int `json:"endColumn"`
}

// item is one result before rule indexes are assigned.
type item struct {
	entry  compiler.Entry
	result result
	rank   int
	order  int
}

// Marshal encodes one run for a subcommand. The output has no timestamp, so the same outcomes give the same bytes.
// A check without a decision path or title fails with build-manifest: that build predates SARIF and needs ipso compile.
func Marshal(version, subcommand string, checks []Check) ([]byte, error) {
	ordered := append([]Check(nil), checks...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Entry.DecisionID != ordered[j].Entry.DecisionID {
			return ordered[i].Entry.DecisionID < ordered[j].Entry.DecisionID
		}
		return ordered[i].Entry.CheckIndex < ordered[j].Entry.CheckIndex
	})
	successful := true
	var items []item
	for _, check := range ordered {
		entry := check.Entry
		if entry.Path == "" || entry.Title == "" {
			return nil, &compiler.Error{Code: compiler.CodeBuildManifest, Err: fmt.Errorf("decision %s has no path or title, run ipso compile", entry.DecisionID)}
		}
		if !compiler.ValidRepoPath(entry.Path) {
			return nil, &compiler.Error{Code: compiler.CodeBuildManifest, Err: fmt.Errorf("decision %s path is not inside the repository", entry.DecisionID)}
		}
		if check.Outcome.Err != nil {
			successful = false
		}
		items = append(items, resultsOf(check)...)
	}
	for i := range items {
		items[i].order = i
	}
	items, omitted := truncate(items)

	rules := []rule{}
	indexes := map[string]int{}
	results := make([]result, 0, len(items))
	for _, one := range items {
		index, ok := indexes[one.result.RuleID]
		if !ok {
			index = len(rules)
			indexes[one.result.RuleID] = index
			rules = append(rules, ruleOf(one.entry, one.result.Level))
		}
		one.result.RuleIndex = index
		results = append(results, one.result)
	}
	var notifications []notification
	if omitted > 0 {
		notifications = []notification{{
			Level:   levelWarning,
			Message: message{Text: fmt.Sprintf("Results omitted: %d. A run holds at most %d, and the terminal lists every violation.", omitted, maxResults)},
		}}
	}
	document := log{
		Schema:  schemaURI,
		Version: "2.1.0",
		Runs: []run{{
			Tool: tool{Driver: driver{
				Name:           "ipso",
				Version:        version,
				InformationURI: "https://github.com/ipsofacto-io/ipso",
				Rules:          rules,
			}},
			AutomationDetails: automationDetails{ID: "ipso/" + subcommand + "/"},
			Invocations:       []invocation{{ExecutionSuccessful: successful, ToolExecutionNotifications: notifications}},
			Results:           results,
		}},
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// resultsOf returns the results of one check. A pass has none. A finding with a position gets its own result.
// Violations without one share a single result on the decision file.
func resultsOf(check Check) []item {
	entry := check.Entry
	if check.Outcome.Err != nil {
		text := fmt.Sprintf("%s: check %d could not be evaluated (%s). See the [decision](%d).", linkText(entry.Title), entry.CheckIndex, errorCode(check.Outcome.Err), decisionLocationID)
		return []item{newItem(entry, levelError, text, decisionPhysical(entry), 1, false)}
	}
	var located []compiler.Position
	unlocated := 0
	for _, violation := range check.Outcome.Violations {
		if violation.Position == nil {
			unlocated++
			continue
		}
		located = append(located, *violation.Position)
	}
	sort.SliceStable(located, func(i, j int) bool {
		if located[i].Path != located[j].Path {
			return located[i].Path < located[j].Path
		}
		if located[i].StartLine != located[j].StartLine {
			return located[i].StartLine < located[j].StartLine
		}
		return located[i].StartColumn < located[j].StartColumn
	})
	level := levelOf(entry.Mode)
	waived := check.Outcome.Waived
	var items []item
	seen := map[string]int{}
	for _, position := range located {
		physical := decisionPhysical(entry)
		if compiler.ValidRepoPath(position.Path) && position.StartLine >= 1 {
			physical = physicalLocation{ArtifactLocation: artifactOf(position.Path), Region: regionOf(position)}
		}
		seen[physical.ArtifactLocation.URI]++
		text := fmt.Sprintf("%s: check %d reported a violation here. See the [decision](%d).", linkText(entry.Title), entry.CheckIndex, decisionLocationID)
		items = append(items, newItem(entry, level, text, physical, seen[physical.ArtifactLocation.URI], waived))
	}
	if unlocated > 0 {
		physical := decisionPhysical(entry)
		seen[physical.ArtifactLocation.URI]++
		text := fmt.Sprintf("%s: check %d failed with %s. See the [decision](%d).", linkText(entry.Title), entry.CheckIndex, violationCount(unlocated), decisionLocationID)
		items = append(items, newItem(entry, level, text, physical, seen[physical.ArtifactLocation.URI], waived))
	}
	return items
}

func newItem(entry compiler.Entry, level, text string, physical physicalLocation, ordinal int, waived bool) item {
	id := ruleID(entry)
	out := result{
		RuleID:    id,
		Level:     level,
		Message:   message{Text: text},
		Locations: []location{{PhysicalLocation: physical}},
		RelatedLocations: []relatedLocation{{
			ID:               decisionLocationID,
			PhysicalLocation: decisionPhysical(entry),
			Message:          message{Text: "Decision record"},
		}},
		PartialFingerprints: fingerprints{PrimaryLocationLineHash: fingerprint(id, physical.ArtifactLocation.URI, ordinal)},
	}
	rank := levelRank(level)
	if waived {
		// GitHub ignores suppressions and leaves the alert open, so the level and the message carry the waiver.
		out.Level = levelNote
		out.Message.Text = "Waived: " + text
		out.Suppressions = []suppression{{Kind: "external", Justification: "A waiver on the decision is in force."}}
		rank = levelRank(levelNote) + 1
	}
	return item{entry: entry, result: out, rank: rank}
}

// truncate keeps the most severe results and returns them in their original order. Waived results go first.
func truncate(items []item) ([]item, int) {
	if len(items) <= maxResults {
		return items, 0
	}
	kept := append([]item(nil), items...)
	sort.SliceStable(kept, func(i, j int) bool {
		return kept[i].rank < kept[j].rank
	})
	omitted := len(kept) - maxResults
	kept = kept[:maxResults]
	sort.Slice(kept, func(i, j int) bool {
		return kept[i].order < kept[j].order
	})
	return kept, omitted
}

func ruleOf(entry compiler.Entry, level string) rule {
	title := limitRunes(oneLine(entry.Title), maxDescriptionRunes)
	return rule{
		ID:               ruleID(entry),
		Name:             limitRunes(oneLine(entry.Slug), maxNameRunes),
		ShortDescription: message{Text: title},
		FullDescription:  message{Text: limitRunes(fmt.Sprintf("Decision %s, check %d: %s", oneLine(entry.DecisionID), entry.CheckIndex, title), maxDescriptionRunes)},
		Help: help{
			Text:     helpText(entry, title),
			Markdown: helpMarkdown(entry, title),
		},
		DefaultConfiguration: defaultConfiguration{Level: level},
		Properties:           ruleProperties{Tags: []string{"ipso", "decision"}},
	}
}

func helpText(entry compiler.Entry, title string) string {
	text := fmt.Sprintf("%s\n\nDecision file: %s", title, oneLine(entry.Path))
	if safeToken.MatchString(entry.Slug) {
		text += "\n\nRun: ipso explain " + entry.Slug
	}
	return text
}

func helpMarkdown(entry compiler.Entry, title string) string {
	text := fmt.Sprintf("**%s**\n\nDecision file: %s", markdownText(title), markdownText(oneLine(entry.Path)))
	if safeToken.MatchString(entry.Slug) {
		text += "\n\nRun `ipso explain " + entry.Slug + "` for the decision text and its links."
	}
	return text
}

func ruleID(entry compiler.Entry) string {
	return oneLine(entry.DecisionID) + "/" + strconv.Itoa(entry.CheckIndex)
}

func levelOf(mode string) string {
	switch mode {
	case "warn":
		return levelWarning
	case "advise":
		return levelNote
	default:
		return levelError
	}
}

func levelRank(level string) int {
	switch level {
	case levelError:
		return 0
	case levelWarning:
		return 1
	default:
		return 2
	}
}

// errorCode returns the stable reason code of err. Error text can repeat engine output, so it is never used.
func errorCode(err error) string {
	code := compiler.CodeOf(err)
	if !safeToken.MatchString(code) {
		return genericErrorCode
	}
	return code
}

func decisionPhysical(entry compiler.Entry) physicalLocation {
	return physicalLocation{
		ArtifactLocation: artifactOf(entry.Path),
		Region:           region{StartLine: 1, StartColumn: 1, EndLine: 1, EndColumn: 2},
	}
}

func artifactOf(path string) artifactLocation {
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		// A colon in the first segment would otherwise read as a URI scheme.
		segments[i] = strings.ReplaceAll(url.PathEscape(segment), ":", "%3A")
	}
	return artifactLocation{URI: strings.Join(segments, "/"), URIBaseID: srcRoot}
}

// regionOf fills the region GitHub requires. A missing or inverted end falls back to the start.
func regionOf(position compiler.Position) region {
	out := region{
		StartLine:   position.StartLine,
		StartColumn: max(position.StartColumn, 1),
		EndLine:     position.EndLine,
		EndColumn:   position.EndColumn,
	}
	if out.EndLine < out.StartLine {
		out.EndLine = out.StartLine
		out.EndColumn = 0
	}
	if out.EndColumn < 1 || (out.EndLine == out.StartLine && out.EndColumn <= out.StartColumn) {
		out.EndColumn = out.StartColumn + 1
	}
	return out
}

func fingerprint(id, uri string, ordinal int) string {
	sum := sha256.Sum256([]byte(id + "\x00" + uri))
	return hex.EncodeToString(sum[:16]) + ":" + strconv.Itoa(ordinal)
}

func violationCount(count int) string {
	if count == 1 {
		return "1 violation"
	}
	return strconv.Itoa(count) + " violations"
}

func oneLine(value string) string {
	return compiler.EscapeControls(value)
}

// linkText escapes a value for a SARIF message, where [text](id) is a link.
func linkText(value string) string {
	return strings.NewReplacer(`\`, `\\`, `[`, `\[`, `]`, `\]`).Replace(limitRunes(oneLine(value), maxDescriptionRunes))
}

// markdownText escapes a value so a decision title cannot add a link, an autolink, an image, HTML, or a mention to the help.
func markdownText(value string) string {
	var buf strings.Builder
	for _, r := range value {
		if strings.ContainsRune("\\`*_{}[]()<>#!|~@&:.", r) {
			buf.WriteByte('\\')
		}
		buf.WriteRune(r)
	}
	return buf.String()
}

func limitRunes(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}
