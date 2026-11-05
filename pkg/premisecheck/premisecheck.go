// Package premisecheck runs the premise probe of ADR-0053 the way `ipso premise check` runs it: one
// public HTTPS GET of a JSON document, a JSON Pointer, and one comparison. It is the entry point for
// callers outside this module that re-check premises on a schedule, such as the ipso-server worker, so
// the CLI and the server share one client, one address policy, and one comparison.
//
// The probe sends no cookies and no Authorization header, does not follow a redirect, refuses unless
// every resolved address is public, and stores nothing. A caller that applies a host allowlist, as the
// server does, decides with Host and does not call Check for a host it refuses.
package premisecheck

import (
	"context"
	"crypto/x509"
	"net"

	"github.com/ipsofacto-io/ipso/internal/premise"
)

// Results of a probe.
const (
	ResultPass  = premise.ResultPass
	ResultFail  = premise.ResultFail
	ResultError = premise.ResultError
)

// Spec is one premise probe. HasEquals is set for an equals comparison, including JSON null. Equals is a
// decoded JSON value; decode numbers as json.Number so a large integer compares exactly. Semver is one
// operator and a version, and is read only when HasEquals is false.
type Spec struct {
	URL       string
	Pointer   string
	Equals    any
	HasEquals bool
	Semver    string
}

// Result is one probe. Observed is compact JSON when a value was read and it fits the limit.
// BodySHA256 is the lowercase hex SHA-256 of the bytes read, set when any were read. Reason is set only
// for an error, and is a short fixed code that holds no content of the probed document.
type Result struct {
	Result     string
	Expected   any
	Observed   []byte
	BodySHA256 string
	Reason     string
}

// Client performs the probe. Lookup, Dial, and Roots are test hooks. The zero value uses the system
// resolver, dials the address it already accepted, and uses the system certificate pool.
type Client struct {
	Lookup func(ctx context.Context, host string) ([]net.IP, error)
	Dial   func(ctx context.Context, network, addr string) (net.Conn, error)
	Roots  *x509.CertPool
}

// Check runs one probe within ten seconds. It is the probe of `ipso premise check`.
func (c Client) Check(ctx context.Context, spec Spec) Result {
	got := premise.Client{Lookup: c.Lookup, Dial: c.Dial, Roots: c.Roots}.Check(ctx, premise.Spec{
		URL:       spec.URL,
		Pointer:   spec.Pointer,
		Equals:    spec.Equals,
		HasEquals: spec.HasEquals,
		Semver:    spec.Semver,
	})
	return Result{
		Result:     got.Result,
		Expected:   got.Expected,
		Observed:   got.Observed,
		BodySHA256: got.BodySHA256,
		Reason:     got.Reason,
	}
}

// Host returns the lowercase host that Check would dial for rawURL, and false when Check would refuse
// the URL: not https, a fragment, userinfo, an IP address as the host, a host outside ASCII, or a port
// other than 443. A caller that compares hosts has to compare this value and no other reading of the URL,
// so the host it allows is the host that is fetched. A trailing dot is kept, so an absolute name never
// equals the same name without it.
func Host(rawURL string) (string, bool) {
	return premise.Host(rawURL)
}
