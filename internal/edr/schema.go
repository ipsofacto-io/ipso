package edr

import _ "embed"

// SchemaURL is the canonical name of the embedded schema, the $id of EDR 1.1.0.
// The file in this package is the artifact to validate against. The URL is not
// fetched.
const SchemaURL = "https://ipsoplatform.io/schema/edr/v1.1.json"

// SchemaJSON is a copy of ipsofacto-io/edr-spec schema/edr-v1.1.schema.json
// (ADR-0159). EDR 1.1.0 accepts every 0.1.0, 0.2.0, and 1.0.0 file unchanged
// and adds engine: llm and check.max_age_days.
//
//go:embed schema/edr-v1.1.schema.json
var SchemaJSON []byte
