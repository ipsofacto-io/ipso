package edr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// publishedSchemaSHA256 is the sha256 of schema/edr-v1.0.schema.json at the
// v1.0.0 tag of ipsofacto-io/edr-spec. That file never changes (ADR-0153), so
// the embedded copy must keep this digest.
const publishedSchemaSHA256 = "d14bff6df550d503738995c3f98d2eb5f474e3322138c2c6e74f78146d65f41e"

func TestEmbeddedSchemaIsTheEDR10File(t *testing.T) {
	sum := sha256.Sum256(SchemaJSON)
	if got := hex.EncodeToString(sum[:]); got != publishedSchemaSHA256 {
		t.Fatalf("embedded schema sha256 = %s, want the EDR 1.0.0 file %s", got, publishedSchemaSHA256)
	}
}

func TestEmbeddedSchemaIDIsSchemaURL(t *testing.T) {
	var header struct {
		ID string `json:"$id"`
	}
	if err := json.Unmarshal(SchemaJSON, &header); err != nil {
		t.Fatal(err)
	}
	if header.ID != SchemaURL {
		t.Fatalf("$id = %q, want SchemaURL %q", header.ID, SchemaURL)
	}
}
