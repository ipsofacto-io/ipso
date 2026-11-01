package checkov

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

// Hit is one Checkov result for a check id.
type Hit struct {
	Resource string
	FilePath string
}

// Results is a Checkov JSON report reduced to the fields ipso reads.
type Results struct {
	Version    string
	Passed     map[string][]Hit
	Failed     map[string][]Hit
	Skipped    map[string][]Hit
	ParseError bool
	raw        []byte
}

// SHA256 returns the digest of the report bytes as they were read.
func (r Results) SHA256() string {
	sum := sha256.Sum256(r.raw)
	return hex.EncodeToString(sum[:])
}

// ReadResults reads one Checkov JSON report.
// It accepts one framework object, an array of framework objects, and the summary object of an empty scan.
func ReadResults(r io.Reader) (Results, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxReportBytes+1))
	if err != nil {
		return Results{}, err
	}
	if len(raw) > MaxReportBytes {
		return Results{}, &compiler.Error{Code: CodeTooLarge, Err: fmt.Errorf("report is larger than %d bytes", MaxReportBytes)}
	}
	doc, err := decodeResults(raw)
	if err != nil {
		return Results{}, err
	}
	doc.raw = raw
	return doc, nil
}

type checkItem struct {
	CheckID  string `json:"check_id"`
	Resource string `json:"resource"`
	FilePath string `json:"file_path"`
}

type framework struct {
	CheckType string `json:"check_type"`
	Results   *struct {
		Passed        []checkItem       `json:"passed_checks"`
		Failed        []checkItem       `json:"failed_checks"`
		Skipped       []checkItem       `json:"skipped_checks"`
		ParsingErrors []json.RawMessage `json:"parsing_errors"`
	} `json:"results"`
	Summary struct {
		ParsingErrors  int    `json:"parsing_errors"`
		CheckovVersion string `json:"checkov_version"`
	} `json:"summary"`
}

func decodeResults(raw []byte) (Results, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return Results{}, &compiler.Error{Code: CodeFormat, Err: fmt.Errorf("expected a Checkov report")}
	}
	if trimmed[0] == '[' {
		var docs []framework
		if err := json.Unmarshal(trimmed, &docs); err != nil || len(docs) == 0 {
			return Results{}, &compiler.Error{Code: CodeFormat, Err: fmt.Errorf("expected a Checkov report")}
		}
		return mergeFrameworks(docs)
	}
	var doc framework
	if err := json.Unmarshal(trimmed, &doc); err != nil {
		return Results{}, &compiler.Error{Code: CodeFormat, Err: fmt.Errorf("expected a Checkov report")}
	}
	if doc.Results == nil && doc.CheckType == "" {
		version, parsing, err := bareSummary(trimmed)
		if err != nil {
			return Results{}, err
		}
		return Results{
			Version:    version,
			Passed:     map[string][]Hit{},
			Failed:     map[string][]Hit{},
			Skipped:    map[string][]Hit{},
			ParseError: parsing,
		}, nil
	}
	if doc.Results == nil {
		return Results{}, &compiler.Error{Code: CodeFormat, Err: fmt.Errorf("expected a Checkov report")}
	}
	return mergeFrameworks([]framework{doc})
}

func bareSummary(raw []byte) (string, bool, error) {
	var doc struct {
		ParsingErrors  int    `json:"parsing_errors"`
		CheckovVersion string `json:"checkov_version"`
		Summary        struct {
			ParsingErrors  int    `json:"parsing_errors"`
			CheckovVersion string `json:"checkov_version"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", false, &compiler.Error{Code: CodeFormat, Err: fmt.Errorf("expected a Checkov report")}
	}
	version := doc.CheckovVersion
	parsing := doc.ParsingErrors
	if version == "" {
		version = doc.Summary.CheckovVersion
	}
	if doc.Summary.ParsingErrors > parsing {
		parsing = doc.Summary.ParsingErrors
	}
	return version, parsing > 0, nil
}

func mergeFrameworks(docs []framework) (Results, error) {
	out := Results{
		Passed:  map[string][]Hit{},
		Failed:  map[string][]Hit{},
		Skipped: map[string][]Hit{},
	}
	for _, doc := range docs {
		if out.Version == "" {
			out.Version = doc.Summary.CheckovVersion
		}
		if doc.Summary.ParsingErrors > 0 || (doc.Results != nil && len(doc.Results.ParsingErrors) > 0) {
			out.ParseError = true
		}
		if doc.Results == nil {
			continue
		}
		if err := addHits(out.Passed, doc.Results.Passed); err != nil {
			return Results{}, err
		}
		if err := addHits(out.Failed, doc.Results.Failed); err != nil {
			return Results{}, err
		}
		if err := addHits(out.Skipped, doc.Results.Skipped); err != nil {
			return Results{}, err
		}
	}
	return out, nil
}

func addHits(dest map[string][]Hit, items []checkItem) error {
	for _, item := range items {
		if item.CheckID == "" {
			return &compiler.Error{Code: CodeFormat, Err: fmt.Errorf("result has no check_id")}
		}
		dest[item.CheckID] = append(dest[item.CheckID], Hit{Resource: item.Resource, FilePath: item.FilePath})
	}
	return nil
}

// EvalCheck compares the compiled check id with the report.
// A failed or skipped result is a violation. An id that was not reported is a violation.
// A parsing error is an evaluation error and is not waived.
func EvalCheck(entry compiler.Entry, artifacts map[string][]byte, results Results, now time.Time) compiler.Outcome {
	if results.ParseError {
		return compiler.Outcome{Err: &compiler.Error{Code: CodeFormat, Err: fmt.Errorf("checkov report has a parsing error")}}
	}
	id, err := bindingID(artifacts)
	if err != nil {
		return compiler.Outcome{Err: err}
	}
	var violations []compiler.Violation
	for _, hit := range results.Failed[id] {
		violations = append(violations, compiler.Violation{Message: hitMessage("failed", id, hit), Identity: []string{"failed", id, hit.Resource, hit.FilePath}})
	}
	for _, hit := range results.Skipped[id] {
		violations = append(violations, compiler.Violation{Message: hitMessage("skipped", id, hit), Identity: []string{"skipped", id, hit.Resource, hit.FilePath}})
	}
	if len(violations) == 0 && len(results.Passed[id]) == 0 {
		violations = append(violations, compiler.Violation{Message: "check not reported: " + id})
	}
	return compiler.Cover(entry, compiler.Outcome{Violations: violations}, now)
}

func hitMessage(kind, id string, hit Hit) string {
	return kind + " " + id + " " + compiler.EscapeControls(hit.Resource) + " " + compiler.EscapeControls(hit.FilePath)
}

func bindingID(artifacts map[string][]byte) (string, error) {
	raw, ok := artifacts[artifactName]
	if !ok {
		return "", &compiler.Error{Code: compiler.CodeBuildManifest, Err: fmt.Errorf("missing %s", artifactName)}
	}
	var doc binding
	if err := json.Unmarshal(raw, &doc); err != nil || doc.CheckID == "" {
		return "", &compiler.Error{Code: compiler.CodeBuildManifest, Err: fmt.Errorf("binding has no check_id")}
	}
	return doc.CheckID, nil
}
