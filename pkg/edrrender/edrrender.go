// Package edrrender renders a decision stored in a registry as an EDR Markdown file. It is the public entry
// point for callers outside this module, such as the ipso-server tenant export, and its output passes
// edrcheck.Validate. Everything else in this module stays internal.
package edrrender

import (
	"time"

	"github.com/ipsofacto-io/ipso/internal/edr"
)

// Decision is one version of a stored decision.
type Decision struct {
	// ID is the EDR id, a ULID. ID makes one from a UUID.
	ID string
	// Body is the JSON object the registry holds. It may lack any field, and it is untrusted text.
	Body []byte
	// ValidFrom and ValidTo bound the valid time of the version. A nil ValidTo does not end.
	ValidFrom time.Time
	ValidTo   *time.Time
}

// ID prints the 16 bytes of a UUID as a ULID. A UUIDv7 keeps its order and every bit. The first character
// of a ULID holds 3 bits, so a first byte of 0x80 or more loses its top bit.
func ID(raw [16]byte) string {
	return edr.ULIDFrom(raw)
}

// Render returns the file for one decision version. A field the body lacks or holds in a form the EDR
// schema refuses is replaced by a default, and the file says so with inferred: true. Text in the body can
// not add a heading or change the frontmatter. An id that is not a ULID or a zero ValidFrom is an error.
func Render(d Decision) (string, error) {
	return edr.RenderDecision(d.ID, d.Body, d.ValidFrom, d.ValidTo)
}
