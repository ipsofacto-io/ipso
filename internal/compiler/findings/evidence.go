package findings

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

// Finding is one open finding id.
type Finding struct {
	ID string
}

// Evidence is one evidence version 1 document for a security tool.
type Evidence struct {
	Tool     string
	Status   string
	Findings []Finding
	raw      []byte
}

// SHA256 returns the digest of the evidence bytes as they were read.
func (e Evidence) SHA256() string {
	sum := sha256.Sum256(e.raw)
	return hex.EncodeToString(sum[:])
}

// ReadEvidence reads one evidence file for tool.
// A file that names another known tool fails with evidence-tool.
func ReadEvidence(r io.Reader, tool string) (Evidence, error) {
	if !Known(tool) {
		return Evidence{}, &compiler.Error{Code: CodeTool, Err: fmt.Errorf("tool %s", tool)}
	}
	raw, err := io.ReadAll(io.LimitReader(r, compiler.MaxRefBytes+1))
	if err != nil {
		return Evidence{}, err
	}
	if len(raw) > compiler.MaxRefBytes {
		return Evidence{}, &compiler.Error{Code: CodeTooLarge, Err: fmt.Errorf("evidence is larger than %d bytes", compiler.MaxRefBytes)}
	}
	doc, err := decodeEvidence(raw)
	if err != nil {
		return Evidence{}, err
	}
	if doc.Tool != tool {
		return Evidence{}, &compiler.Error{Code: CodeTool, Err: fmt.Errorf("evidence tool %s", doc.Tool)}
	}
	doc.raw = raw
	return doc, nil
}

type findingFile struct {
	ID string `json:"id"`
}

type evidenceFile struct {
	EvidenceVersion int           `json:"evidence_version"`
	Tool            string        `json:"tool"`
	Status          string        `json:"status"`
	Findings        []findingFile `json:"findings"`
}

func decodeEvidence(raw []byte) (Evidence, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc evidenceFile
	if err := dec.Decode(&doc); err != nil {
		return Evidence{}, &compiler.Error{Code: CodeFormat, Err: fmt.Errorf("expected evidence version 1")}
	}
	if dec.More() {
		return Evidence{}, &compiler.Error{Code: CodeFormat, Err: fmt.Errorf("expected one JSON value")}
	}
	if doc.EvidenceVersion != 1 || !Known(doc.Tool) || (doc.Status != statusSuccess && doc.Status != statusFailed) || doc.Findings == nil {
		return Evidence{}, &compiler.Error{Code: CodeFormat, Err: fmt.Errorf("expected evidence version 1")}
	}
	findings := make([]Finding, 0, len(doc.Findings))
	for _, item := range doc.Findings {
		if !validID(item.ID) {
			return Evidence{}, &compiler.Error{Code: CodeFormat, Err: fmt.Errorf("finding id %q", item.ID)}
		}
		findings = append(findings, Finding{ID: item.ID})
	}
	return Evidence{Tool: doc.Tool, Status: doc.Status, Findings: findings}, nil
}

// EvalCheck compares the compiled finding id with the evidence.
// An id that appears on a finished scan is a violation. A scan that did not finish is an error.
func EvalCheck(entry compiler.Entry, artifacts map[string][]byte, evidence Evidence, now time.Time) compiler.Outcome {
	if evidence.Status == statusFailed {
		return compiler.Outcome{Err: &compiler.Error{Code: CodeScanFailed, Err: fmt.Errorf("scan failed")}}
	}
	id, err := bindingID(artifacts)
	if err != nil {
		return compiler.Outcome{Err: err}
	}
	var violations []compiler.Violation
	for _, finding := range evidence.Findings {
		if finding.ID == id {
			violations = append(violations, compiler.Violation{Message: "open finding: " + compiler.EscapeControls(id)})
		}
	}
	return compiler.Cover(entry, compiler.Outcome{Violations: violations}, now)
}
