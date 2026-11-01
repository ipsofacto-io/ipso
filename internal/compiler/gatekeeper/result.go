package gatekeeper

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ipsofacto-io/ipso/internal/compiler"
	"github.com/ipsofacto-io/ipso/internal/compiler/opa"
)

const (
	resultTarget       = "admission.k8s.gatekeeper.sh"
	templateAPI        = "templates.gatekeeper.sh/v1"
	templateKind       = "ConstraintTemplate"
	constraintAPI      = "constraints.gatekeeper.sh/v1beta1"
	denyAction         = "deny"
	noResults          = "null"
	fallbackMessage    = "constraint violated"
	fallbackObjectName = "(unnamed)"
)

// Finding is one object that violated the constraint.
type Finding struct {
	// Object is namespace/kind/name, or kind/name for an object with no namespace.
	Object  string
	Message string
}

type objectRef struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
}

func (o objectRef) label() string {
	name := o.Metadata.Name
	if name == "" {
		name = fallbackObjectName
	}
	if o.Metadata.Namespace == "" {
		return o.Kind + "/" + name
	}
	return o.Metadata.Namespace + "/" + o.Kind + "/" + name
}

type resultItem struct {
	Target     *string         `json:"target"`
	Msg        string          `json:"msg"`
	Constraint *objectRef      `json:"constraint"`
	Action     *string         `json:"enforcementAction"`
	Scoped     json.RawMessage `json:"scopedActions"`
	Violating  *objectRef      `json:"violatingObject"`
	Trace      json.RawMessage `json:"trace"`
}

// ParseResults reads the standard output of one `gator test -o json` run for the constraint id, and
// returns the objects that violated it. exit is the process status.
//
// Gator prints the JSON `null` when nothing violated a constraint, and otherwise one array with a
// result for each constraint and object. Its exit status is 1 when a result has the action deny and 0
// otherwise. Anything else is an error: another constraint, another action, a result that carries
// scoped actions or a trace, an array with no result, text around the array, and an exit status that
// disagrees with the results.
//
// A constraint with no match.kinds reviews every object gator reads, including ipso's own template and
// constraint. Those results count for the exit status and are not findings.
func ParseResults(raw []byte, exit int, id opa.Gatekeeper) ([]Finding, error) {
	if exit != 0 && exit != 1 {
		return nil, &compiler.Error{Code: CodeRun, Err: fmt.Errorf("exit status %d", exit)}
	}
	if len(raw) == 0 {
		if exit == 1 {
			return nil, &compiler.Error{Code: CodeRun, Err: errors.New("exit status 1 and no result")}
		}
		return nil, outputError("the output is empty")
	}
	if string(bytes.TrimRight(raw, " \t\r\n")) == noResults {
		if exit != 0 {
			return nil, outputError("exit status and results disagree")
		}
		return nil, nil
	}
	results, err := decodeResults(raw)
	if err != nil {
		return nil, err
	}
	for i, item := range results {
		if err := checkResult(item, id); err != nil {
			return nil, outputError(fmt.Sprintf("result %d: %s", i+1, err))
		}
	}
	if (id.Action == denyAction) != (exit == 1) {
		return nil, outputError("exit status and results disagree")
	}
	return findingsOf(results, id)
}

// decodeResults reads exactly one JSON array. A line before it and anything after it are errors.
func decodeResults(raw []byte) ([]resultItem, error) {
	if raw[0] != '[' {
		return nil, outputError("the output does not start with the results")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var results []resultItem
	if err := dec.Decode(&results); err != nil {
		return nil, outputError("the output is not the results")
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, outputError("the output has more than the results")
	}
	if len(results) == 0 {
		return nil, outputError("the results are an empty array")
	}
	return results, nil
}

func checkResult(item resultItem, id opa.Gatekeeper) error {
	switch {
	case item.Target == nil || *item.Target != resultTarget:
		return errors.New("it is not for the admission target")
	case item.Constraint == nil || item.Constraint.APIVersion != constraintAPI ||
		item.Constraint.Kind != id.Kind || item.Constraint.Metadata.Name != id.Name:
		return errors.New("it names another constraint")
	case item.Action == nil || *item.Action != id.Action:
		return errors.New("it has another enforcement action")
	case len(item.Scoped) != 0:
		return errors.New("it has scoped actions")
	case len(item.Trace) != 0 && string(item.Trace) != "null":
		return errors.New("it has a trace")
	case item.Violating == nil || item.Violating.APIVersion == "" || item.Violating.Kind == "":
		return errors.New("its object has no apiVersion or kind")
	}
	return nil
}

func findingsOf(results []resultItem, id opa.Gatekeeper) ([]Finding, error) {
	var findings []Finding
	for i, item := range results {
		switch {
		case isOwnObject(*item.Violating, id):
			continue
		case strings.Contains(strings.ToLower(item.Violating.APIVersion), gatekeeperDomain):
			return nil, outputError(fmt.Sprintf("result %d: it reviews a Gatekeeper object that ipso did not supply", i+1))
		}
		message := item.Msg
		if message == "" {
			message = fallbackMessage
		}
		findings = append(findings, Finding{Object: item.Violating.label(), Message: message})
	}
	return findings, nil
}

// isOwnObject reports whether object is the template or the constraint ipso passed to gator.
// Compile requires the template name to be the lower case of the constraint kind.
func isOwnObject(object objectRef, id opa.Gatekeeper) bool {
	template := object.APIVersion == templateAPI && object.Kind == templateKind && object.Metadata.Name == strings.ToLower(id.Kind)
	constraint := object.APIVersion == constraintAPI && object.Kind == id.Kind && object.Metadata.Name == id.Name
	return template || constraint
}

func outputError(reason string) error {
	return &compiler.Error{Code: CodeOutput, Err: errors.New(reason)}
}

// violation is the terminal line of a finding. Control characters are escaped so it stays on one line.
// The verdict report never carries it.
func (f Finding) violation() compiler.Violation {
	return compiler.Violation{
		Address:  compiler.EscapeControls(f.Object),
		Message:  compiler.EscapeControls(f.Message),
		Identity: []string{f.Object},
	}
}
