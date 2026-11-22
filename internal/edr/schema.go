package edr

import _ "embed"

// SchemaURL is the canonical name of the embedded schema, the $id of EDR 1.0.0.
// The file in this package is the artifact to validate against. The URL is not
// fetched.
const SchemaURL = "https://ipsoplatform.io/schema/edr/v1.json"

// SchemaJSON is a copy of ipsofacto-io/edr-spec schema/edr-v1.0.schema.json at
// the v1.0.0 tag. EDR 1.0.0 accepts exactly the documents draft 0.2.0 accepts,
// which includes a 0.1 file. A published schema file never changes from 1.0.0
// on, so the copy stays byte for byte equal to that tag.
//
//go:embed schema/edr-v1.0.schema.json
var SchemaJSON []byte
