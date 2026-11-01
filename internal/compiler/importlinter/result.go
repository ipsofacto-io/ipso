package importlinter

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/toolrun"
)

const (
	// CodeMissing means python is not on PATH, or it cannot import import-linter and grimp.
	CodeMissing = "importlinter-missing"
	// CodeVersion means import-linter or grimp is not the pinned release, or the check was compiled for another release.
	CodeVersion = "importlinter-version"
	// CodePath means a named source directory is missing, is not a directory, or leaves the repository,
	// a root package is in two of them, or the tree holds a symlink, a file that is not regular, or more
	// Python source than the cap.
	CodePath = "importlinter-path"
	// CodeEmpty means a root package has no __init__.py in the named directories, or the run analysed no file.
	CodeEmpty = "importlinter-empty"
	// CodeRun means python or import-linter did not finish, or import-linter reported an error instead of a result.
	CodeRun = "importlinter-run"
	// CodeOutput means the run produced output ipso cannot trust: a report that is not the shape ipso reads,
	// one that disagrees with the exit status, or output over the cap.
	CodeOutput = "importlinter-output"
)

const (
	typeForbidden = "forbidden"
	typeAcyclic   = "acyclic_siblings"

	contractsHeading = "Contracts"
	brokenHeading    = "Broken contracts"
	cyclesPrefix     = "No cycles are allowed in "
)

var (
	analyzed = regexp.MustCompile(`^Analyzed ([0-9]+) files, [0-9]+ dependencies\.$`)
	summary  = regexp.MustCompile(`^Contracts: ([0-9]+) kept, ([0-9]+) broken\.$`)
)

// Finding is one violation import-linter reported for a contract.
type Finding struct {
	// Contract is the contract id, the section name in importlinter.ini.
	Contract string
	// Line is the rendered line that counts as the violation.
	Line string
}

// lineMarker is the line list import-linter renders after an import, such as (l.1) or (l.1, l.3).
var lineMarker = regexp.MustCompile(`\s*\(l\.\d+(?:, l\.\d+)*\)`)

// identity leaves out the line list, so an import that moves keeps its fingerprint.
func (f Finding) identity() []string {
	return []string{f.Contract, lineMarker.ReplaceAllString(f.Line, "")}
}

func (f Finding) message() string {
	return compiler.EscapeControls(f.Contract) + " " + compiler.EscapeControls(f.Line)
}

// ParseOutput reads the standard output of one lint_imports run and returns the violations.
// exit is the process status: 0 when every contract is kept and 1 when one is broken or the engine failed.
//
// The pinned release prints this shape when stdout is not a terminal and Rich is set to plain text:
// the Contracts heading, "Analyzed N files, M dependencies.", one "<name> KEPT|BROKEN" line per
// contract in file order, "Contracts: K kept, B broken.", and, when B is above 0, a "Broken contracts"
// heading with one section per broken contract. Anything else is an error, and so is an exit status
// that disagrees with the contract lines.
func ParseOutput(raw []byte, exit int, canon Canonical) ([]Finding, error) {
	if exit != 0 && exit != 1 {
		return nil, &compiler.Error{Code: CodeRun, Err: fmt.Errorf("exit status %d", exit)}
	}
	if bytes.IndexByte(raw, 0x1b) >= 0 {
		return nil, outputError("the output carries a terminal escape")
	}
	lines := trimBlank(strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n"))
	start := reportStart(lines)
	switch {
	case start < 0 && exit == 0:
		return nil, outputError("the run printed no report")
	case start < 0:
		// import-linter prints its own error, such as a module that does not exist, instead of a report.
		return nil, &compiler.Error{Code: CodeRun, Err: errors.New(toolrun.Excerpt([]byte(oneLine(lines)), "import-linter failed"))}
	case start > 0:
		return nil, outputError("the output has lines before the report")
	}
	return parseReport(lines, exit, canon)
}

func parseReport(lines []string, exit int, canon Canonical) ([]Finding, error) {
	r := &reader{lines: lines, pos: 3}
	r.skipBlank()
	text, _ := r.take()
	match := analyzed.FindStringSubmatch(text)
	if match == nil || !r.takeIs(underline(len(text))) {
		return nil, outputError("expected the file count")
	}
	files, err := strconv.Atoi(match[1])
	if err != nil {
		return nil, outputError("the file count is not a number")
	}
	r.skipBlank()

	var broken []int
	kept := 0
	for i, contract := range canon.Contracts {
		text, _ := r.take()
		verdict := resultLine(contract.Name).FindStringSubmatch(text)
		if verdict == nil {
			return nil, outputError(fmt.Sprintf("contract %d has no result line", i+1))
		}
		if verdict[1] == "KEPT" {
			kept++
		} else {
			broken = append(broken, i)
		}
	}
	r.skipBlank()
	text, _ = r.take()
	totals := summary.FindStringSubmatch(text)
	if totals == nil || totals[1] != strconv.Itoa(kept) || totals[2] != strconv.Itoa(len(broken)) {
		return nil, outputError("the summary does not match the contract lines")
	}
	if (len(broken) > 0) != (exit == 1) {
		return nil, outputError("exit status and report disagree")
	}
	if files == 0 {
		return nil, &compiler.Error{Code: CodeEmpty, Err: errors.New("import-linter analysed no file")}
	}
	r.skipBlank()
	if len(broken) == 0 {
		if !r.done() {
			return nil, outputError("the output has lines after the summary")
		}
		return nil, nil
	}
	return parseBroken(r, canon, broken)
}

func parseBroken(r *reader, canon Canonical, broken []int) ([]Finding, error) {
	if !r.takeIs(underline(len(brokenHeading))) || !r.takeIs(brokenHeading) || !r.takeIs(underline(len(brokenHeading))) {
		return nil, outputError("expected the Broken contracts heading")
	}
	r.skipBlank()
	rest := r.lines[r.pos:]
	var findings []Finding
	for n, index := range broken {
		contract := canon.Contracts[index]
		if len(rest) < 2 || !headingIs(rest[0], contract.Name) || rest[1] != underline(len(contract.Name)) {
			return nil, outputError(fmt.Sprintf("expected the section of contract %d", index+1))
		}
		rest = rest[2:]
		end := len(rest)
		if n+1 < len(broken) {
			end = sectionAt(rest, canon.Contracts[broken[n+1]].Name)
			if end < 0 {
				return nil, outputError(fmt.Sprintf("expected the section of contract %d", broken[n+1]+1))
			}
		}
		found := violations(contract, rest[:end])
		if len(found) == 0 {
			return nil, outputError(fmt.Sprintf("contract %d is broken and lists no violation", index+1))
		}
		findings = append(findings, found...)
		rest = rest[end:]
	}
	return findings, nil
}

// violations counts the lines the pinned release prints once for each violation. A forbidden contract
// starts a chain with "-   ", the other contracts with "- ". An acyclic_siblings contract prints one
// "No cycles are allowed" line for each package, and the dependencies under it are the way out,
// which the engine cuts off at five, so they are not counted.
func violations(contract Contract, body []string) []Finding {
	var found []Finding
	for _, line := range body {
		switch {
		case contract.Type == typeAcyclic && strings.HasPrefix(line, cyclesPrefix):
			found = append(found, Finding{Contract: contract.ID, Line: line})
		case contract.Type == typeForbidden && strings.HasPrefix(line, "-   "):
			found = append(found, Finding{Contract: contract.ID, Line: strings.TrimSpace(line[1:])})
		case contract.Type != typeForbidden && contract.Type != typeAcyclic && strings.HasPrefix(line, "- "):
			found = append(found, Finding{Contract: contract.ID, Line: strings.TrimSpace(line[1:])})
		}
	}
	return found
}

// resultLine matches "<name> KEPT" or "<name> BROKEN", with the count of ignored imports that
// import-linter appends. A warning suffix does not match. Compile keeps unmatched_ignore_imports_alerting
// at error, so import-linter never warns about a contract of this build.
func resultLine(name string) *regexp.Regexp {
	return regexp.MustCompile(`^` + regexp.QuoteMeta(name) + ` (KEPT|BROKEN)(?: \([0-9]+ ignored imports?\))?$`)
}

func outputError(reason string) error {
	return &compiler.Error{Code: CodeOutput, Err: errors.New(reason)}
}

func underline(n int) string { return strings.Repeat("-", n) }

// reportStart returns the index of the line that opens the Contracts heading, or -1.
func reportStart(lines []string) int {
	for i := 1; i+1 < len(lines); i++ {
		if lines[i] == contractsHeading && lines[i-1] == underline(len(contractsHeading)) && lines[i+1] == underline(len(contractsHeading)) {
			return i - 1
		}
	}
	return -1
}

// sectionAt returns the index of the heading of the contract name in lines, or -1.
func sectionAt(lines []string, name string) int {
	for i := 0; i+1 < len(lines); i++ {
		if headingIs(lines[i], name) && lines[i+1] == underline(len(name)) {
			return i
		}
	}
	return -1
}

// headingIs reports whether line is the heading import-linter prints for the contract name. The heading
// is printed as [bold]name[/bold] through Rich markup, so backslashes at the end of a name escape the
// closing tag or are halved, and the heading no longer shows the name verbatim. The underline is as long
// as the name, which is what keeps the heading from being confused with other text.
func headingIs(line, name string) bool {
	base := strings.TrimRight(name, `\`)
	if base == name {
		return line == name
	}
	rest, ok := strings.CutPrefix(line, base)
	if !ok {
		return false
	}
	return strings.Trim(strings.TrimSuffix(rest, "[/bold]"), `\`) == ""
}

func trimBlank(lines []string) []string {
	for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		lines = lines[1:]
	}
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// oneLine joins the non-blank lines with a space, so a message that spans lines reads as one excerpt.
func oneLine(lines []string) string {
	parts := make([]string, 0, len(lines))
	for _, line := range lines {
		if text := strings.TrimSpace(line); text != "" {
			parts = append(parts, text)
		}
	}
	return strings.Join(parts, " ")
}

type reader struct {
	lines []string
	pos   int
}

func (r *reader) done() bool { return r.pos >= len(r.lines) }

func (r *reader) skipBlank() {
	for !r.done() && strings.TrimSpace(r.lines[r.pos]) == "" {
		r.pos++
	}
}

// take returns the next line, or an empty string at the end.
func (r *reader) take() (string, bool) {
	if r.done() {
		return "", false
	}
	line := r.lines[r.pos]
	r.pos++
	return line, true
}

func (r *reader) takeIs(want string) bool {
	line, ok := r.take()
	return ok && line == want
}
