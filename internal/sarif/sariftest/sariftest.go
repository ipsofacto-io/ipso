// Package sariftest validates SARIF output in tests. Only test files import it, so the schema stays out of the binary.
package sariftest

import (
	"bytes"
	_ "embed"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// schemaJSON is the unmodified OASIS SARIF 2.1.0 schema, errata 01, from
// https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json
//
// sha256 c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e
//
//go:embed testdata/sarif-schema-2.1.0.json
var schemaJSON []byte

// Validate fails the test when raw does not validate against the schema.
func Validate(t *testing.T, raw []byte) {
	t.Helper()
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
	if err != nil {
		t.Fatal(err)
	}
	schemaCompiler := jsonschema.NewCompiler()
	if err := schemaCompiler.AddResource("sarif.json", document); err != nil {
		t.Fatal(err)
	}
	schema, err := schemaCompiler.Compile("sarif.json")
	if err != nil {
		t.Fatal(err)
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(value); err != nil {
		t.Fatalf("schema: %v\n%s", err, raw)
	}
}
