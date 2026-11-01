// Package adapter turns the plan and template formats of other IaC tools into one input document for
// repository Rego. The shape is a subset of `terraform show -json`, so a policy reads
// input.resource_changes the same way for every tool (ADR-0066). Adapters parse and do not evaluate:
// no parameter is resolved, no expression is run, and nothing is fetched.
package adapter

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

const (
	// CodeFormat means the input is not what the adapter reads.
	CodeFormat = "adapter-format"
	// CodeTooLarge means the input is larger than MaxBytes.
	CodeTooLarge = "adapter-too-large"

	// MaxBytes is the largest input an adapter reads. It is the cap of a Terraform plan.
	MaxBytes = 256 << 20

	maxDepth = 128

	formatVersion = "1.0"
	modeManaged   = "managed"
	actionCreate  = "create"
)

// Targets are the check targets the adapters serve.
const (
	TargetPulumi         = "pulumi-preview"
	TargetCloudFormation = "cloudformation-template"
	TargetARM            = "arm-template"
)

// Document is what a policy reads as input.
type Document struct {
	FormatVersion   string           `json:"format_version"`
	Adapter         string           `json:"adapter"`
	ResourceChanges []ResourceChange `json:"resource_changes"`
}

// ResourceChange is one resource. Address names it in a violation. Attributes holds what the tool
// declares beside the resource's own values, such as a CloudFormation DeletionPolicy.
type ResourceChange struct {
	Address    string         `json:"address"`
	Mode       string         `json:"mode"`
	Type       string         `json:"type"`
	Name       string         `json:"name"`
	Change     Change         `json:"change"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// Change is what happens to the resource. A template has no plan, so its action is always create.
type Change struct {
	Actions      []string       `json:"actions"`
	Before       any            `json:"before"`
	After        any            `json:"after"`
	AfterUnknown map[string]any `json:"after_unknown"`
}

// Read reads one input, at most MaxBytes.
func Read(r io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxBytes {
		return nil, &compiler.Error{Code: CodeTooLarge, Err: fmt.Errorf("input is larger than %d bytes", MaxBytes)}
	}
	return raw, nil
}

func encode(name string, resources []ResourceChange) ([]byte, error) {
	if resources == nil {
		resources = []ResourceChange{}
	}
	raw, err := json.Marshal(Document{FormatVersion: formatVersion, Adapter: name, ResourceChanges: resources})
	if err != nil {
		return nil, formatErr("the input cannot be encoded")
	}
	return raw, nil
}

func formatErr(format string, args ...any) error {
	return &compiler.Error{Code: CodeFormat, Err: fmt.Errorf(format, args...)}
}

// parseJSON decodes one JSON document and refuses anything after it.
func parseJSON(raw []byte, what string, into any) error {
	if err := json.Unmarshal(raw, into); err != nil {
		return formatErr("expected %s", what)
	}
	return nil
}
