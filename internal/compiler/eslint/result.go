package eslint

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/toolrun"
)

const (
	// CodeMissing means eslint is not on PATH, is not in a node_modules directory outside the repository,
	// or cannot report its version, or the TypeScript packages a check needs are not installed next to it.
	CodeMissing = "eslint-missing"
	// CodeVersion means the binary or a TypeScript package is not the pinned release, the version output
	// is not the shape ipso reads, or the check was compiled for another release.
	CodeVersion = "eslint-version"
	// CodeRun means eslint did not finish, or exited without results.
	CodeRun = "eslint-run"
	// CodeOutput means the run produced output ipso cannot trust: something other than one result list,
	// a suppressed message, a message that is not one of this check's rules, or a list that disagrees with
	// its own counts or the exit status.
	CodeOutput = "eslint-output"
	// CodeIncomplete means ESLint reported a fatal message, such as a parse error, so that file was not checked.
	CodeIncomplete = "eslint-incomplete"
	// CodeEmpty means ESLint linted no file.
	CodeEmpty = "eslint-empty"
)

const (
	severityWarn  = 1
	severityError = 2
)

// Finding is one message of one rule on one file.
type Finding struct {
	Rule string
	// Path is slash-separated and relative to the repository root.
	Path      string
	Line      int
	Column    int
	EndLine   int
	EndColumn int
	Message   string
}

type fileResult struct {
	FilePath           *string            `json:"filePath"`
	Messages           *[]message         `json:"messages"`
	SuppressedMessages *[]json.RawMessage `json:"suppressedMessages"`
	ErrorCount         *int               `json:"errorCount"`
	WarningCount       *int               `json:"warningCount"`
	FatalErrorCount    *int               `json:"fatalErrorCount"`
}

type message struct {
	RuleID    *string `json:"ruleId"`
	Severity  *int    `json:"severity"`
	Fatal     bool    `json:"fatal"`
	Message   string  `json:"message"`
	Line      *int    `json:"line"`
	Column    *int    `json:"column"`
	EndLine   *int    `json:"endLine"`
	EndColumn *int    `json:"endColumn"`
}

// ParseResults reads the standard output of one `eslint --format json` run for a check that enables
// the rules in rules at the severity of mode. root is the repository root with symlinks resolved.
// exit is the process status: 0 when no message has severity error, and 1 when one has.
//
// The pinned release prints one list with one result for each file it linted, whether or not the file has
// a message. A result carries the messages, the messages a suppression hid, and counts. Every message of a
// rule is checked against the rules ipso compiled and the severity of the mode, and the counts and the exit
// status must agree with the messages. A suppressed message is refused: it is a finding that a file of the
// repository hid. A fatal message, such as a parse error, means the file was not checked. Anything else is an error.
func ParseResults(raw []byte, exit int, rules map[string]struct{}, mode, root string) ([]Finding, error) {
	if exit != 0 && exit != 1 {
		return nil, &compiler.Error{Code: CodeRun, Err: fmt.Errorf("exit status %d", exit)}
	}
	want, err := wantSeverity(mode)
	if err != nil {
		return nil, outputError(err.Error())
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		if exit == 1 {
			return nil, &compiler.Error{Code: CodeRun, Err: errors.New("exit status 1 and no results")}
		}
		return nil, outputError("the output is empty")
	}
	results, err := decodeResults(raw)
	if err != nil {
		return nil, err
	}
	var findings []Finding
	var fatal *Finding
	errorMessages := 0
	for i, result := range results {
		path, err := checkFile(result, root)
		if err != nil {
			return nil, outputError(fmt.Sprintf("result %d: %s", i+1, err))
		}
		counts := tally{}
		for _, item := range *result.Messages {
			if item.Severity == nil || (*item.Severity != severityWarn && *item.Severity != severityError) {
				return nil, outputError(fmt.Sprintf("%s: a message has no severity of warn or error", path))
			}
			counts.add(item)
			if item.Fatal {
				if fatal == nil {
					fatal = &Finding{Path: path, Message: item.Message}
				}
				continue
			}
			finding, err := checkMessage(item, path, rules, want)
			if err != nil {
				return nil, outputError(fmt.Sprintf("%s: %s", path, err))
			}
			findings = append(findings, finding)
		}
		if counts.errors != *result.ErrorCount || counts.warnings != *result.WarningCount || counts.fatals != *result.FatalErrorCount {
			return nil, outputError(path + ": the counts do not match the messages")
		}
		errorMessages += counts.errors
	}
	if len(results) == 0 {
		if exit == 1 {
			return nil, outputError("exit status 1 and no results")
		}
		return nil, &compiler.Error{Code: CodeEmpty, Err: errors.New("eslint linted no file")}
	}
	if (errorMessages > 0) != (exit == 1) {
		return nil, outputError("exit status and results disagree")
	}
	if fatal != nil {
		return nil, incompleteError(*fatal)
	}
	return findings, nil
}

func wantSeverity(mode string) (int, error) {
	severity, err := severityFor(mode)
	if err != nil {
		return 0, err
	}
	if severity == "error" {
		return severityError, nil
	}
	return severityWarn, nil
}

// decodeResults reads exactly one JSON list. A line before it and anything after it are errors.
func decodeResults(raw []byte) ([]fileResult, error) {
	text := bytes.TrimLeft(raw, " \t\r\n")
	if len(text) == 0 || text[0] != '[' {
		return nil, outputError("the output does not start with a list of results")
	}
	dec := json.NewDecoder(bytes.NewReader(text))
	var results []fileResult
	if err := dec.Decode(&results); err != nil {
		return nil, outputError("the output is not a list of results")
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, outputError("the output has more than the list of results")
	}
	return results, nil
}

// checkFile checks one result and returns the path of its file, relative to root.
func checkFile(result fileResult, root string) (string, error) {
	switch {
	case result.FilePath == nil || *result.FilePath == "":
		return "", errors.New("no file path")
	case result.Messages == nil || result.ErrorCount == nil || result.WarningCount == nil || result.FatalErrorCount == nil:
		return "", errors.New("a field is missing")
	case result.SuppressedMessages == nil:
		return "", errors.New("no list of suppressed messages")
	}
	path, ok := relativeTo(root, *result.FilePath)
	if !ok {
		return "", errors.New("a file outside the repository")
	}
	if len(*result.SuppressedMessages) > 0 {
		return "", fmt.Errorf("%s: a suppression hid a message", path)
	}
	return path, nil
}

// relativeTo returns file relative to root, with slashes. A path that is not under root lexically is
// resolved once, so a spelling of the root that differs from the one ESLint reports is not a refusal.
func relativeTo(root, file string) (string, bool) {
	if !filepath.IsAbs(file) {
		return "", false
	}
	if rel, ok := within(root, filepath.Clean(file)); ok && rel != "." {
		return filepath.ToSlash(rel), true
	}
	resolved, err := filepath.EvalSymlinks(file)
	if err != nil {
		return "", false
	}
	if rel, ok := within(root, resolved); ok && rel != "." {
		return filepath.ToSlash(rel), true
	}
	return "", false
}

// within returns p relative to root, and false when p is not root or below it.
func within(root, p string) (string, bool) {
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}

type tally struct {
	errors, warnings, fatals int
}

func (t *tally) add(item message) {
	if *item.Severity == severityError {
		t.errors++
	} else {
		t.warnings++
	}
	if item.Fatal {
		t.fatals++
	}
}

func checkMessage(item message, path string, rules map[string]struct{}, want int) (Finding, error) {
	switch {
	case item.RuleID == nil:
		return Finding{}, errors.New("a message has no rule")
	case *item.Severity != want:
		return Finding{}, errors.New("a message has the severity of another mode")
	case item.Line == nil || *item.Line < 1 || item.Column == nil || *item.Column < 1:
		return Finding{}, errors.New("a message has no position")
	}
	if _, ok := rules[*item.RuleID]; !ok {
		return Finding{}, errors.New("a message is not one of this check's rules")
	}
	finding := Finding{Rule: *item.RuleID, Path: path, Line: *item.Line, Column: *item.Column, Message: item.Message}
	if item.EndLine != nil && item.EndColumn != nil {
		finding.EndLine, finding.EndColumn = *item.EndLine, *item.EndColumn
	}
	return finding, nil
}

func outputError(reason string) error {
	return &compiler.Error{Code: CodeOutput, Err: errors.New(reason)}
}

func incompleteError(f Finding) error {
	text := f.Path + ": " + f.Message
	return &compiler.Error{Code: CodeIncomplete, Err: errors.New(toolrun.Excerpt([]byte(text), "a file was not checked"))}
}

// violation is the terminal line of a finding. Control characters are escaped so it stays on one line.
// The verdict report never carries it.
func (f Finding) violation() compiler.Violation {
	line := fmt.Sprintf("%s %s:%d:%d: %s", compiler.EscapeControls(f.Rule), compiler.EscapeControls(f.Path), f.Line, f.Column, compiler.EscapeControls(f.Message))
	position := &compiler.Position{Path: f.Path, StartLine: f.Line, StartColumn: f.Column, EndLine: f.EndLine, EndColumn: f.EndColumn}
	return compiler.Violation{Message: line, Position: position, Identity: []string{f.Rule, f.Path}}
}
