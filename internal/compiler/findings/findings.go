// Package findings compiles a Snyk, Wiz, SonarQube, or Dependabot finding id into a binding ipso evaluates offline.
package findings

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ipsofacto-io/ipso/internal/compiler"
)

const (
	// CodeID means ref is not a finding id.
	CodeID = "finding-id"
	// CodeFormat means the evidence file is not evidence version 1.
	CodeFormat = "evidence-format"
	// CodeTooLarge means the evidence file is larger than compiler.MaxRefBytes.
	CodeTooLarge = "evidence-too-large"
	// CodeTool means the evidence file names another tool.
	CodeTool = "evidence-tool"
	// CodeScanFailed means the scan did not finish.
	CodeScanFailed = "scan-failed"

	artifactName  = "binding.json"
	version       = "1"
	maxFindingID  = 128
	statusSuccess = "success"
	statusFailed  = "failed"
)

// Compiler is one security-tool engine. The four constructors share the evidence contract.
type Compiler struct {
	engine string
}

// Snyk returns the snyk compiler.
func Snyk() Compiler { return Compiler{engine: "snyk"} }

// Wiz returns the wiz compiler.
func Wiz() Compiler { return Compiler{engine: "wiz"} }

// SonarQube returns the sonarqube compiler.
func SonarQube() Compiler { return Compiler{engine: "sonarqube"} }

// Dependabot returns the dependabot compiler.
func Dependabot() Compiler { return Compiler{engine: "dependabot"} }

// Engine returns the EDR engine value this compiler handles.
func (c Compiler) Engine() string { return c.engine }

// Version returns the evidence contract version. Compile does not call the scanner.
func (Compiler) Version() string { return version }

// Compile writes binding.json with the finding id in ref.
// target and job are ignored. The framework stamps target on the manifest unchanged.
func (c Compiler) Compile(in compiler.Input) ([]compiler.Artifact, error) {
	id := in.Check.Ref
	if id == "" {
		return nil, &compiler.Error{Code: compiler.CodeRefRequired, Err: fmt.Errorf("%s requires ref", c.engine)}
	}
	if !validID(id) {
		return nil, &compiler.Error{Code: CodeID, Err: fmt.Errorf("ref %q", id)}
	}
	raw, err := marshalBinding(binding{FindingID: id})
	if err != nil {
		return nil, err
	}
	return []compiler.Artifact{{Name: artifactName, Data: raw}}, nil
}

type binding struct {
	FindingID string `json:"finding_id"`
}

func marshalBinding(value binding) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func validID(id string) bool {
	if id == "" || len(id) > maxFindingID || !utf8.ValidString(id) || id != strings.TrimSpace(id) {
		return false
	}
	for _, r := range id {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Known reports whether tool is one of the four engines.
func Known(tool string) bool {
	switch tool {
	case "snyk", "wiz", "sonarqube", "dependabot":
		return true
	default:
		return false
	}
}

// bindingID reads the finding id the compiler wrote.
func bindingID(artifacts map[string][]byte) (string, error) {
	raw, ok := artifacts[artifactName]
	if !ok {
		return "", &compiler.Error{Code: compiler.CodeBuildManifest, Err: fmt.Errorf("missing %s", artifactName)}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc binding
	if err := dec.Decode(&doc); err != nil || dec.More() || !validID(doc.FindingID) {
		return "", &compiler.Error{Code: compiler.CodeBuildManifest, Err: fmt.Errorf("binding has no finding id")}
	}
	return doc.FindingID, nil
}
