package kyverno

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/toolrun"
)

const (
	// CodeMissing means kyverno is not on PATH, or its version command failed.
	CodeMissing = "kyverno-missing"
	// CodeVersion means the binary is not the pinned release, the version output is not the shape ipso
	// reads, or the check was compiled for another release.
	CodeVersion = "kyverno-version"
	// CodePath means a named path is missing, is not a manifest file or a directory, or leaves the
	// repository, or the tree holds a symlink, a file that is not regular, or more manifest bytes than the cap.
	CodePath = "kyverno-path"
	// CodeEmpty means the named paths hold no .yaml or .yml file.
	CodeEmpty = "kyverno-empty"
	// CodeRun means kyverno did not finish, or exited without a report.
	CodeRun = "kyverno-run"
	// CodeOutput means the run produced output ipso cannot trust: something other than one report,
	// a report that does not name this policy, or one that disagrees with its own summary or the exit status.
	CodeOutput = "kyverno-output"
	// CodeIncomplete means Kyverno reported an error for a resource, so that resource was not checked.
	CodeIncomplete = "kyverno-incomplete"
)

const (
	reportKind       = "ClusterReport"
	reportAPIVersion = "openreports.io/v1alpha1"
	reportSource     = "KyvernoValidatingPolicy"

	resultPass  = "pass"
	resultFail  = "fail"
	resultSkip  = "skip"
	resultError = "error"

	fallbackMessage = "validation failed"
)

// Finding is one resource that failed the policy.
type Finding struct {
	// Resource is namespace/kind/name, or kind/name for a resource with no namespace.
	Resource string
	Message  string
}

type reportDocument struct {
	Kind       *string          `json:"kind"`
	APIVersion *string          `json:"apiVersion"`
	Summary    *summaryDocument `json:"summary"`
	Results    *[]resultItem    `json:"results"`
}

type summaryDocument struct {
	Pass  *int `json:"pass"`
	Fail  *int `json:"fail"`
	Warn  *int `json:"warn"`
	Error *int `json:"error"`
	Skip  *int `json:"skip"`
}

type resultItem struct {
	Source    *string         `json:"source"`
	Policy    *string         `json:"policy"`
	Result    *string         `json:"result"`
	Message   string          `json:"message"`
	Resources *[]resourceItem `json:"resources"`
}

type resourceItem struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func (r resourceItem) label() string {
	if r.Namespace == "" {
		return r.Kind + "/" + r.Name
	}
	return r.Namespace + "/" + r.Kind + "/" + r.Name
}

// ParseReport reads the standard output of one `kyverno apply --policy-report --output-format json` run
// for the policy named policy, and returns the resources that failed it. exit is the process status:
// 0 when no resource failed or errored, and 1 otherwise.
//
// The pinned release prints nothing when no loaded resource matches the policy, and otherwise one
// ClusterReport: a summary and one result for each policy and resource, with the policy name, the
// resource, and the message of the first validation that failed. Deny, Warn, and Audit all report fail.
// Anything else is an error, and so is an exit status that disagrees with the results.
func ParseReport(raw []byte, exit int, policy string) ([]Finding, error) {
	if exit != 0 && exit != 1 {
		return nil, &compiler.Error{Code: CodeRun, Err: fmt.Errorf("exit status %d", exit)}
	}
	if len(raw) == 0 {
		if exit == 1 {
			return nil, &compiler.Error{Code: CodeRun, Err: errors.New("exit status 1 and no report")}
		}
		// No loaded resource matched the policy, so nothing was checked and nothing failed.
		return nil, nil
	}
	doc, err := decodeReport(raw)
	if err != nil {
		return nil, err
	}
	results, err := checkReport(doc, policy)
	if err != nil {
		return nil, err
	}
	var fails, errs int
	for _, item := range results {
		switch *item.Result {
		case resultFail:
			fails++
		case resultError:
			errs++
		}
	}
	if (fails+errs > 0) != (exit == 1) {
		return nil, outputError("exit status and report disagree")
	}
	if errs > 0 {
		return nil, incompleteError(results)
	}
	var findings []Finding
	for _, item := range results {
		if *item.Result != resultFail {
			continue
		}
		findings = append(findings, Finding{Resource: (*item.Resources)[0].label(), Message: messageOf(item)})
	}
	return findings, nil
}

// decodeReport reads exactly one JSON object. A line before it, such as a banner, and anything after it
// are errors.
func decodeReport(raw []byte) (reportDocument, error) {
	if raw[0] != '{' {
		return reportDocument{}, outputError("the output does not start with a report")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var doc reportDocument
	if err := dec.Decode(&doc); err != nil {
		return reportDocument{}, outputError("the output is not a report")
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return reportDocument{}, outputError("the output has more than the report")
	}
	return doc, nil
}

// checkReport checks the shape of the report and returns its results.
func checkReport(doc reportDocument, policy string) ([]resultItem, error) {
	if doc.Kind == nil || *doc.Kind != reportKind || doc.APIVersion == nil || *doc.APIVersion != reportAPIVersion {
		return nil, outputError("the output is not a ClusterReport")
	}
	if doc.Results == nil || len(*doc.Results) == 0 || doc.Summary == nil {
		return nil, outputError("the report has no results or no summary")
	}
	tally := map[string]int{}
	for i, item := range *doc.Results {
		if err := checkResult(item, policy); err != nil {
			return nil, outputError(fmt.Sprintf("result %d: %s", i+1, err))
		}
		tally[*item.Result]++
	}
	s := doc.Summary
	if s.Pass == nil || s.Fail == nil || s.Warn == nil || s.Error == nil || s.Skip == nil ||
		*s.Pass != tally[resultPass] || *s.Fail != tally[resultFail] || *s.Warn != 0 || *s.Error != tally[resultError] || *s.Skip != tally[resultSkip] {
		return nil, outputError("the summary does not match the results")
	}
	return *doc.Results, nil
}

func checkResult(item resultItem, policy string) error {
	switch {
	case item.Source == nil || *item.Source != reportSource:
		return errors.New("not a Kyverno policy result")
	case item.Policy == nil || *item.Policy != policy:
		return errors.New("it names another policy")
	case item.Result == nil:
		return errors.New("no result")
	case item.Resources == nil || len(*item.Resources) != 1:
		return errors.New("it does not name exactly one resource")
	case (*item.Resources)[0].Kind == "" || (*item.Resources)[0].Name == "":
		return errors.New("its resource has no kind or name")
	}
	switch *item.Result {
	case resultPass, resultFail, resultSkip, resultError:
		return nil
	default:
		// warn is refused too: ipso never passes --audit-warn, so a warning is not a verdict it knows.
		return errors.New("unknown result")
	}
}

func incompleteError(results []resultItem) error {
	for _, item := range results {
		if *item.Result == resultError {
			text := (*item.Resources)[0].label() + ": " + messageOf(item)
			return &compiler.Error{Code: CodeIncomplete, Err: errors.New(toolrun.Excerpt([]byte(text), "a resource was not checked"))}
		}
	}
	return &compiler.Error{Code: CodeIncomplete, Err: errors.New("a resource was not checked")}
}

func messageOf(item resultItem) string {
	if item.Message == "" {
		return fallbackMessage
	}
	return item.Message
}

func outputError(reason string) error {
	return &compiler.Error{Code: CodeOutput, Err: errors.New(reason)}
}

// violation is the terminal line of a finding. Control characters are escaped so it stays on one line.
// The verdict report never carries it.
func (f Finding) violation() compiler.Violation {
	return compiler.Violation{
		Address:  compiler.EscapeControls(f.Resource),
		Message:  compiler.EscapeControls(f.Message),
		Identity: []string{f.Resource},
	}
}
