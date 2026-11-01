package semgrep

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strconv"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

const (
	// CodeMissing means semgrep is not on PATH or its version command failed.
	CodeMissing = "semgrep-missing"
	// CodeVersion means the binary version is not the pin, or the report names a different version.
	CodeVersion = "semgrep-version"
	// CodeRun means the scan did not finish.
	CodeRun = "semgrep-run"
	// CodeOutput means the scan output is not a report ipso can read, or it is larger than the cap.
	CodeOutput = "semgrep-output"
	// CodeIncomplete means Semgrep reported an error or skipped a rule, so some code was not checked.
	CodeIncomplete = "semgrep-incomplete"
	// CodeEmpty means the scan checked no files.
	CodeEmpty = "semgrep-empty"
	// CodePath means a named path resolves through a symlink to a location outside the repository.
	CodePath = "semgrep-path"
)

// Finding is one Semgrep result.
type Finding struct {
	Rule      string
	Path      string
	Line      int
	Column    int
	EndLine   int
	EndColumn int
}

// Result is the part of a scan report ipso evaluates.
type Result struct {
	Version  string
	Scanned  int
	Findings []Finding
}

type scanDocument struct {
	Version *string       `json:"version"`
	Results *[]scanResult `json:"results"`
	Errors  *[]struct {
		Message string `json:"message"`
	} `json:"errors"`
	Paths *struct {
		Scanned []string `json:"scanned"`
	} `json:"paths"`
	SkippedRules *[]struct {
		RuleID string `json:"rule_id"`
	} `json:"skipped_rules"`
}

type scanResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
		Col  int `json:"col"`
	} `json:"start"`
	End struct {
		Line int `json:"line"`
		Col  int `json:"col"`
	} `json:"end"`
}

// ParseResult reads a Semgrep JSON report.
// toolVersion is the output of semgrep --version. The report must name that same version.
// An error or a skipped rule wins over an empty scan: skipped files are not a clean tree.
func ParseResult(raw []byte, toolVersion string) (Result, error) {
	var doc scanDocument
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Version == nil || doc.Results == nil || doc.Errors == nil || doc.Paths == nil || doc.SkippedRules == nil {
		return Result{}, &compiler.Error{Code: CodeOutput, Err: errors.New("expected a scan report")}
	}
	if *doc.Version != toolVersion {
		return Result{}, &compiler.Error{Code: CodeVersion, Err: fmt.Errorf("report version %s, binary %s", *doc.Version, toolVersion)}
	}
	if len(*doc.Errors) > 0 || len(*doc.SkippedRules) > 0 {
		return Result{}, &compiler.Error{Code: CodeIncomplete, Err: errors.New("scan did not check every file")}
	}
	if len(doc.Paths.Scanned) == 0 {
		if len(*doc.Results) > 0 {
			return Result{}, &compiler.Error{Code: CodeOutput, Err: errors.New("scan report has findings and no scanned files")}
		}
		return Result{}, &compiler.Error{Code: CodeEmpty, Err: errors.New("scan checked no files")}
	}
	findings := make([]Finding, 0, len(*doc.Results))
	for _, item := range *doc.Results {
		if item.CheckID == "" || item.Path == "" || item.Start.Line < 1 {
			return Result{}, &compiler.Error{Code: CodeOutput, Err: errors.New("result is missing a rule, a path, or a line")}
		}
		findings = append(findings, Finding{Rule: item.CheckID, Path: item.Path, Line: item.Start.Line, Column: item.Start.Col, EndLine: item.End.Line, EndColumn: item.End.Col})
	}
	return Result{Version: *doc.Version, Scanned: len(doc.Paths.Scanned), Findings: findings}, nil
}

// EvalCheck compares one compiled check with one scan report.
// An in-force waiver covers findings. An error is never waived.
func EvalCheck(entry compiler.Entry, artifacts map[string][]byte, toolVersion string, raw []byte, now time.Time) compiler.Outcome {
	if _, ok := artifacts[ArtifactName]; !ok {
		return compiler.Outcome{Err: &compiler.Error{Code: compiler.CodeBuildManifest, Err: fmt.Errorf("missing %s", ArtifactName)}}
	}
	if toolVersion != entry.CompilerVersion {
		return compiler.Outcome{Err: &compiler.Error{Code: CodeVersion, Err: fmt.Errorf("semgrep %s is not %s", toolVersion, entry.CompilerVersion)}}
	}
	result, err := ParseResult(raw, toolVersion)
	if err != nil {
		return compiler.Outcome{Err: err}
	}
	var violations []compiler.Violation
	for _, item := range result.Findings {
		violations = append(violations, compiler.Violation{Message: item.message(), Position: item.position()})
	}
	return compiler.Cover(entry, compiler.Outcome{Violations: violations}, now)
}

func (f Finding) position() *compiler.Position {
	return &compiler.Position{Path: path.Clean(f.Path), StartLine: f.Line, StartColumn: f.Column, EndLine: f.EndLine, EndColumn: f.EndColumn}
}

func (f Finding) message() string {
	return compiler.EscapeControls(f.Rule) + " " + compiler.EscapeControls(f.Path) + ":" + strconv.Itoa(f.Line)
}
