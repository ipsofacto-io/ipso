package archunit

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

const (
	// CodeMissing means java or javac is not on PATH, or its version command failed.
	CodeMissing = "archunit-missing"
	// CodeVersion means the JDK is older than 17 or its version is unreadable, or the check was compiled for another ArchUnit release.
	CodeVersion = "archunit-version"
	// CodeJar means a pinned jar is missing, too large, or does not match its sha256.
	CodeJar = "archunit-jar"
	// CodePath means a named class directory is missing, is not a directory, leaves the repository,
	// holds a symlink, or holds more class files than the cap.
	CodePath = "archunit-path"
	// CodeEmpty means the test checked no classes.
	CodeEmpty = "archunit-empty"
	// CodeRun means javac or the JVM did not finish, or a rule raised an exception.
	CodeRun = "archunit-run"
	// CodeOutput means the run produced output ipso cannot trust: no report, a report that does not
	// match the test, or output over the cap.
	CodeOutput = "archunit-output"
)

const assertionError = "java.lang.AssertionError"

var emptyLayer = regexp.MustCompile(`^Layer '[a-z0-9-]+' is empty$`)

var violated = regexp.MustCompile(`^Architecture Violation \[Priority: [A-Z]+\] - Rule '([a-z0-9-]+)' was violated \(([0-9]+) times\):$`)

// Finding is one violation line ArchUnit reported for a rule.
type Finding struct {
	Rule string
	Line string
}

type suite struct {
	XMLName xml.Name   `xml:"testsuite"`
	Cases   []testCase `xml:"testcase"`
}

type testCase struct {
	Name      string     `xml:"name,attr"`
	ClassName string     `xml:"classname,attr"`
	Failures  []detail   `xml:"failure"`
	Errors    []detail   `xml:"error"`
	Skipped   []struct{} `xml:"skipped"`
}

type detail struct {
	Type    string `xml:"type,attr"`
	Message string `xml:"message,attr"`
}

// Evaluate runs one compiled check and applies its waivers.
// The check runs the canonical test regenerated from the verified artifact, never a repository file.
func (e *Env) Evaluate(ctx context.Context, entry compiler.Entry, artifacts map[string][]byte, now time.Time) compiler.Outcome {
	if entry.CompilerVersion != version {
		return compiler.Outcome{Err: &compiler.Error{Code: CodeVersion, Err: fmt.Errorf("check compiled for archunit %s, ipso runs %s", entry.CompilerVersion, version)}}
	}
	source, ok := artifacts[artifactName]
	if !ok {
		return compiler.Outcome{Err: &compiler.Error{Code: compiler.CodeBuildManifest, Err: fmt.Errorf("missing %s", artifactName)}}
	}
	test, err := ReadCanonical(entry.DecisionID, entry.CheckIndex, source)
	if err != nil {
		return compiler.Outcome{Err: err}
	}
	if !e.classes.hasClassesUnder(test.Packages) {
		return compiler.Outcome{Err: &compiler.Error{Code: CodeEmpty, Err: errors.New("no class file under the imported packages")}}
	}
	raw, exit, err := e.run(ctx, test, source)
	if err != nil {
		return compiler.Outcome{Err: err}
	}
	findings, err := ParseReport(raw, exit, test)
	if err != nil {
		return compiler.Outcome{Err: err}
	}
	var violations []compiler.Violation
	for _, item := range findings {
		violations = append(violations, compiler.Violation{Message: item.message(), Identity: item.identity()})
	}
	return compiler.Cover(entry, compiler.Outcome{Violations: violations}, now)
}

// renderedLineNumber is the line number ArchUnit puts at the end of a rendered line, such as (A.java:3).
var renderedLineNumber = regexp.MustCompile(`:\d+\)$`)

// identity leaves out the source line, so a finding that moves keeps its fingerprint.
func (f Finding) identity() []string {
	return []string{f.Rule, renderedLineNumber.ReplaceAllString(f.Line, ")")}
}

func (f Finding) message() string {
	return compiler.EscapeControls(f.Rule) + " " + compiler.EscapeControls(f.Line)
}

// ParseReport reads the JUnit XML the console wrote and returns the violations of every rule.
// exit is the console status: 0 when every rule passed, 1 when a rule failed.
// A rule that checked no classes, raised an exception, or is missing from the report is an error,
// and so is a report that does not agree with the exit status.
func ParseReport(raw []byte, exit int, test Canonical) ([]Finding, error) {
	var doc suite
	if err := xml.Unmarshal(raw, &doc); err != nil {
		return nil, outputError("expected a JUnit report")
	}
	methods := make(map[string]string, len(test.Rules))
	for _, rule := range test.Rules {
		methods[methodName(rule)+"()"] = rule
	}
	byRule := make(map[string]testCase, len(test.Rules))
	for _, item := range doc.Cases {
		rule, ok := methods[item.Name]
		if !ok || item.ClassName != test.Class {
			return nil, outputError("report names a test that is not in the canonical test")
		}
		if _, dup := byRule[rule]; dup {
			return nil, outputError("report lists a rule twice")
		}
		byRule[rule] = item
	}
	var findings []Finding
	for _, rule := range test.Rules {
		item, ok := byRule[rule]
		if !ok {
			return nil, outputError("report does not list every rule")
		}
		got, err := ruleFindings(rule, test.Layers[rule], item)
		if err != nil {
			return nil, err
		}
		findings = append(findings, got...)
	}
	if (len(findings) > 0) != (exit == 1) {
		return nil, outputError("exit status and report disagree")
	}
	return findings, nil
}

// ruleFindings reads the outcome of one rule. layers is the number of layers of a layers rule, and 0 for a forbidden rule.
// A rule that checked no class is an error, so is a layers rule in which every layer is empty.
// An error names the rule, so a check with several rules says which one broke.
func ruleFindings(rule string, layers int, item testCase) ([]Finding, error) {
	switch {
	case len(item.Skipped) > 0:
		return nil, outputError("rule " + rule + " was skipped")
	case len(item.Errors) > 0:
		return nil, &compiler.Error{Code: CodeRun, Err: errors.New("rule " + rule + " raised an exception")}
	case len(item.Failures) == 0:
		return nil, nil
	case len(item.Failures) > 1 || item.Failures[0].Type != assertionError:
		return nil, outputError("rule " + rule + " failed in a way ipso does not read")
	}
	message := strings.ReplaceAll(item.Failures[0].Message, "\r\n", "\n")
	if strings.HasPrefix(message, "Rule '"+rule+"' failed to check any classes. ") {
		return nil, &compiler.Error{Code: CodeEmpty, Err: errors.New("rule " + rule + " checked no classes")}
	}
	head, rest, hasLines := strings.Cut(message, "\n")
	match := violated.FindStringSubmatch(head)
	if match == nil || match[1] != rule || !hasLines {
		return nil, outputError("rule " + rule + " failed in a way ipso does not read")
	}
	count, err := strconv.Atoi(match[2])
	lines := strings.Split(rest, "\n")
	if err != nil || count < 1 || len(lines) != count {
		return nil, outputError("rule " + rule + " reports a violation count that does not match its lines")
	}
	if layers > 0 && len(lines) == layers && allMatch(lines, emptyLayer) {
		return nil, &compiler.Error{Code: CodeEmpty, Err: errors.New("no layer of rule " + rule + " holds a class")}
	}
	findings := make([]Finding, len(lines))
	for i, line := range lines {
		findings[i] = Finding{Rule: rule, Line: line}
	}
	return findings, nil
}

func allMatch(lines []string, pattern *regexp.Regexp) bool {
	for _, line := range lines {
		if !pattern.MatchString(line) {
			return false
		}
	}
	return true
}

func outputError(reason string) error {
	return &compiler.Error{Code: CodeOutput, Err: errors.New(reason)}
}

// readReport reads the JUnit XML report, at most limit bytes.
func readReport(path string, limit int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, outputError("the console wrote no report")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, outputError("the report is not a regular file")
	}
	body, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, outputError("the report cannot be read")
	}
	if len(body) > limit {
		return nil, outputError(fmt.Sprintf("the report is larger than %d bytes", limit))
	}
	return body, nil
}
