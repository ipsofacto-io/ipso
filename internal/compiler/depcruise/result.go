package depcruise

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/toolrun"
)

const (
	// CodeMissing means depcruise is not on PATH or its version command failed.
	CodeMissing = "depcruise-missing"
	// CodeVersion means the binary version is outside the caret range, or the report names a different version.
	CodeVersion = "depcruise-version"
	// CodeRun means the cruise did not finish.
	CodeRun = "depcruise-run"
	// CodeOutput means the cruise output is not a report ipso can read, or it is larger than the cap.
	CodeOutput = "depcruise-output"
	// CodeEnvironment means dependency-cruiser reported an environment issue, so sources may have been skipped.
	CodeEnvironment = "depcruise-environment"
	// CodeEmpty means the cruise found no modules.
	CodeEmpty = "depcruise-empty"
)

// Violation is one dependency-cruiser finding whose severity is not ignore.
type Violation struct {
	Rule     string
	From     string
	To       string
	Severity string
}

// Result is the part of a cruise report ipso evaluates.
type Result struct {
	Version    string
	Cruised    int
	Violations []Violation
}

// VersionFits reports whether found satisfies a caret range of pin: the same major, and not lower.
func VersionFits(found, pin string) bool {
	fMajor, fMinor, fPatch, ok := toolrun.ParseSemver(found)
	if !ok {
		return false
	}
	pMajor, pMinor, pPatch, ok := toolrun.ParseSemver(pin)
	if !ok {
		return false
	}
	if fMajor != pMajor || fMinor < pMinor {
		return false
	}
	if fMinor == pMinor && fPatch < pPatch {
		return false
	}
	return true
}

type cruiseSummary struct {
	Violations   *[]cruiseViolation `json:"violations"`
	TotalCruised *int               `json:"totalCruised"`
	Environment  *struct {
		Version string `json:"version"`
		Issues  []struct {
			Name string `json:"name"`
		} `json:"issues"`
	} `json:"environment"`
}

type cruiseViolation struct {
	From string `json:"from"`
	To   string `json:"to"`
	Rule struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"rule"`
}

// ParseResult reads a dependency-cruiser JSON report.
// toolVersion is the output of depcruise --version. The report must name that same version.
// Environment issues win over an empty cruise: a missing compiler is not a clean tree.
func ParseResult(raw []byte, toolVersion string) (Result, error) {
	var doc struct {
		Summary *cruiseSummary `json:"summary"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Summary == nil {
		return Result{}, &compiler.Error{Code: CodeOutput, Err: errors.New("expected a cruise report")}
	}
	summary := doc.Summary
	if summary.Violations == nil || summary.TotalCruised == nil || summary.Environment == nil || summary.Environment.Version == "" {
		return Result{}, &compiler.Error{Code: CodeOutput, Err: errors.New("cruise report is missing a summary field")}
	}
	if summary.Environment.Version != toolVersion {
		return Result{}, &compiler.Error{Code: CodeVersion, Err: fmt.Errorf("report version %s, binary %s", summary.Environment.Version, toolVersion)}
	}
	if len(summary.Environment.Issues) > 0 {
		return Result{}, &compiler.Error{Code: CodeEnvironment, Err: fmt.Errorf("%s", compiler.EscapeControls(summary.Environment.Issues[0].Name))}
	}
	if *summary.TotalCruised < 0 {
		return Result{}, &compiler.Error{Code: CodeOutput, Err: errors.New("totalCruised is negative")}
	}
	if *summary.TotalCruised == 0 {
		return Result{}, &compiler.Error{Code: CodeEmpty, Err: errors.New("cruise found no modules")}
	}
	violations := make([]Violation, 0, len(*summary.Violations))
	for _, item := range *summary.Violations {
		if item.Rule.Name == "" || item.From == "" {
			return Result{}, &compiler.Error{Code: CodeOutput, Err: errors.New("violation is missing a rule or a module")}
		}
		if item.Rule.Severity == "ignore" {
			continue
		}
		violations = append(violations, Violation{
			Rule:     item.Rule.Name,
			From:     item.From,
			To:       item.To,
			Severity: item.Rule.Severity,
		})
	}
	return Result{Version: summary.Environment.Version, Cruised: *summary.TotalCruised, Violations: violations}, nil
}

// EvalCheck compares one compiled check with one cruise report.
// An in-force waiver covers violations. An error is never waived.
func EvalCheck(entry compiler.Entry, artifacts map[string][]byte, toolVersion string, raw []byte, now time.Time) compiler.Outcome {
	if _, ok := artifacts[artifactName]; !ok {
		return compiler.Outcome{Err: &compiler.Error{Code: compiler.CodeBuildManifest, Err: fmt.Errorf("missing %s", artifactName)}}
	}
	if !VersionFits(toolVersion, entry.CompilerVersion) {
		return compiler.Outcome{Err: &compiler.Error{Code: CodeVersion, Err: fmt.Errorf("depcruise %s does not satisfy ^%s", toolVersion, entry.CompilerVersion)}}
	}
	result, err := ParseResult(raw, toolVersion)
	if err != nil {
		return compiler.Outcome{Err: err}
	}
	var violations []compiler.Violation
	for _, item := range result.Violations {
		violations = append(violations, compiler.Violation{Message: item.message(), Identity: []string{item.Rule, item.From, item.To}})
	}
	return compiler.Cover(entry, compiler.Outcome{Violations: violations}, now)
}

func (v Violation) message() string {
	rule := compiler.EscapeControls(v.Rule)
	from := compiler.EscapeControls(v.From)
	if v.To == "" || v.To == v.From {
		return rule + " " + from
	}
	return rule + " " + from + " -> " + compiler.EscapeControls(v.To)
}
