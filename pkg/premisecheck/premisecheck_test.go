package premisecheck_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/ipsofacto-io/ipso/internal/premise"
	"github.com/ipsofacto-io/ipso/internal/premise/premisetest"
	"github.com/ipsofacto-io/ipso/pkg/premisecheck"
)

const host = "status.example.com"

func TestCheckPassFailAndError(t *testing.T) {
	srv, pool := premisetest.Server(t, host, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/moved":
			http.Redirect(w, r, "https://status.example.com/platform.json", http.StatusFound)
		case "/gone":
			http.NotFound(w, r)
		default:
			_, _ = w.Write([]byte(`{"major":16,"name":"postgres","version":"16.4.0"}`))
		}
	}))
	client := pinned(srv, pool, nil)
	cases := []struct {
		name   string
		spec   premisecheck.Spec
		result string
		reason string
	}{
		{"equals holds", equals("/platform.json", "/major", json.Number("16")), premisecheck.ResultPass, ""},
		{"equals does not hold", equals("/platform.json", "/major", json.Number("15")), premisecheck.ResultFail, ""},
		{"semver holds", semver("/platform.json", "/version", ">=16.0.0"), premisecheck.ResultPass, ""},
		{"semver does not hold", semver("/platform.json", "/version", "<16.0.0"), premisecheck.ResultFail, ""},
		{"a redirect is an error", equals("/moved", "/major", json.Number("16")), premisecheck.ResultError, premise.ReasonRedirect},
		{"a status outside 2xx is an error", equals("/gone", "/major", json.Number("16")), premisecheck.ResultError, premise.ReasonStatus},
		{"a missing pointer is an error", equals("/platform.json", "/minor", json.Number("1")), premisecheck.ResultError, premise.ReasonPointer},
		{"a value of the wrong type is an error", equals("/platform.json", "/name", json.Number("1")), premisecheck.ResultError, premise.ReasonType},
		{"a URL the probe refuses is an error", premisecheck.Spec{URL: "http://" + host + "/platform.json", Pointer: "/major"}, premisecheck.ResultError, premise.ReasonURL},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := client.Check(t.Context(), test.spec)
			if got.Result != test.result || got.Reason != test.reason {
				t.Fatalf("result %q reason %q, want %q and %q", got.Result, got.Reason, test.result, test.reason)
			}
			if test.result != premisecheck.ResultError && (len(got.Observed) == 0 || len(got.BodySHA256) != 64) {
				t.Fatalf("a pass or a fail keeps the observed value and the body hash: %+v", got)
			}
		})
	}
}

func TestCheckSendsNoCredentialsAndDialsTheAddressItAccepted(t *testing.T) {
	var mu sync.Mutex
	var header http.Header
	srv, pool := premisetest.Server(t, host, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		header = r.Header.Clone()
		mu.Unlock()
		_, _ = w.Write([]byte(`{"major":16}`))
	}))
	var dialed string
	client := pinned(srv, pool, &dialed)
	got := client.Check(t.Context(), equals("/platform.json", "/major", json.Number("16")))
	if got.Result != premisecheck.ResultPass {
		t.Fatalf("result %+v", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if header.Get("Authorization") != "" || header.Get("Cookie") != "" || header.Get("Proxy-Authorization") != "" {
		t.Fatalf("the probe sent credentials: %v", header)
	}
	if header.Get("User-Agent") != "ipso-premise" {
		t.Fatalf("user agent %q", header.Get("User-Agent"))
	}
	if dialed != "1.1.1.1:443" {
		t.Fatalf("dialed %q, want the accepted address on 443", dialed)
	}
}

func TestCheckNeverDialsAnAddressThatIsNotPublic(t *testing.T) {
	for _, ip := range []string{"10.0.0.1", "169.254.169.254", "64:ff9b::a00:1", "2002:a00:1::", "::10.0.0.1"} {
		t.Run(ip, func(t *testing.T) {
			dialed := false
			client := premisecheck.Client{
				Lookup: func(context.Context, string) ([]net.IP, error) {
					return []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP(ip)}, nil
				},
				Dial: func(context.Context, string, string) (net.Conn, error) {
					dialed = true
					return nil, context.Canceled
				},
			}
			got := client.Check(t.Context(), equals("/platform.json", "/major", json.Number("16")))
			if got.Result != premisecheck.ResultError || got.Reason != premise.ReasonPrivate || dialed {
				t.Fatalf("result %+v dialed %v", got, dialed)
			}
		})
	}
}

func TestCheckComparesAnIntegerBeyondAFloatExactly(t *testing.T) {
	srv, pool := premisetest.Server(t, host, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":9007199254740993}`))
	}))
	client := pinned(srv, pool, nil)
	if got := client.Check(t.Context(), equals("/a", "/id", json.Number("9007199254740993"))); got.Result != premisecheck.ResultPass {
		t.Fatalf("the same integer: %+v", got)
	}
	if got := client.Check(t.Context(), equals("/a", "/id", json.Number("9007199254740992"))); got.Result != premisecheck.ResultFail {
		t.Fatalf("the neighbouring integer: %+v", got)
	}
}

// The package is a wrapper. Whatever the CLI's client says about a document, this one says too.
func TestCheckAgreesWithTheCLIProbe(t *testing.T) {
	srv, pool := premisetest.Server(t, host, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(`{"major":16,"version":"16.4.0","null":null,"list":[1,2]}`))
	}))
	cli := premise.Client{
		Roots:  pool,
		Lookup: publicLookup,
		Dial:   dialTo(srv, nil),
	}
	pkg := pinned(srv, pool, nil)
	specs := []premisecheck.Spec{
		equals("/a", "/major", json.Number("16")),
		equals("/a", "/major", json.Number("17")),
		equals("/a", "/null", nil),
		equals("/a", "/list", []any{json.Number("1"), json.Number("2")}),
		semver("/a", "/version", ">=16.4.0"),
		semver("/a", "/version", ">16.4.0"),
		semver("/a", "/major", ">=1.0.0"),
		equals("/moved", "/major", json.Number("16")),
		equals("/a", "/absent", json.Number("1")),
	}
	for _, spec := range specs {
		want := cli.Check(t.Context(), premise.Spec{
			URL: spec.URL, Pointer: spec.Pointer, Equals: spec.Equals, HasEquals: spec.HasEquals, Semver: spec.Semver,
		})
		got := pkg.Check(t.Context(), spec)
		if got.Result != want.Result || got.Reason != want.Reason || got.BodySHA256 != want.BodySHA256 ||
			string(got.Observed) != string(want.Observed) || !reflect.DeepEqual(got.Expected, want.Expected) {
			t.Errorf("%s %s: package %+v, CLI %+v", spec.URL, spec.Pointer, got, want)
		}
	}
}

func TestHostIsTheHostCheckDials(t *testing.T) {
	good := map[string]string{
		"https://status.example.com/a":        "status.example.com",
		"https://Status.Example.COM/a?b=1":    "status.example.com",
		"https://status.example.com:443/a":    "status.example.com",
		"https://status.example.com":          "status.example.com",
		"https://status.example.com./a":       "status.example.com.",
		"https://a-b.c.example.com/x/y.json":  "a-b.c.example.com",
		"https://xn--bcher-kva.example/a":     "xn--bcher-kva.example",
		"https://status.example.com/a%2Fb?x=": "status.example.com",
	}
	for raw, want := range good {
		got, ok := premisecheck.Host(raw)
		if !ok || got != want {
			t.Errorf("%s: host %q ok %v, want %q", raw, got, ok, want)
		}
	}
	bad := []string{
		"",
		"http://status.example.com/a",
		"https://status.example.com:8443/a",
		"https://user@status.example.com/a",
		"https://user:pass@status.example.com/a",
		"https://status.example.com/a#x",
		"https://1.1.1.1/a",
		"https://[2606:4700::1111]/a",
		"https:///a",
		"status.example.com/a",
		"https://status.example.com\\@evil.example/a",
		"https://status.example\u212a.com/a",
		"https://b\u00fccher.example/a",
		"https://status.exa%C3%A9mple.com/a",
	}
	for _, raw := range bad {
		if got, ok := premisecheck.Host(raw); ok {
			t.Errorf("%q gave host %q", raw, got)
		}
	}
}

// Unicode case folding turns the Kelvin sign into an ASCII k. A host the probe would dial under one name
// must never be reported under another.
func TestACaseFoldedHostIsRefusedAndNeverDialed(t *testing.T) {
	dialed := false
	client := premisecheck.Client{
		Lookup: publicLookup,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, context.Canceled
		},
	}
	got := client.Check(t.Context(), premisecheck.Spec{
		URL: "https://status.example\u212a.com/platform.json", Pointer: "/major", Equals: json.Number("16"), HasEquals: true,
	})
	if got.Result != premisecheck.ResultError || got.Reason != premise.ReasonURL || dialed {
		t.Fatalf("result %+v dialed %v", got, dialed)
	}
}

func equals(path, pointer string, value any) premisecheck.Spec {
	return premisecheck.Spec{URL: "https://" + host + path, Pointer: pointer, Equals: value, HasEquals: true}
}

func semver(path, pointer, constraint string) premisecheck.Spec {
	return premisecheck.Spec{URL: "https://" + host + path, Pointer: pointer, Semver: constraint}
}

func publicLookup(context.Context, string) ([]net.IP, error) {
	return []net.IP{net.ParseIP("1.1.1.1")}, nil
}

func dialTo(srv *httptest.Server, dialed *string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if dialed != nil {
			*dialed = addr
		}
		var d net.Dialer
		return d.DialContext(ctx, network, srv.Listener.Addr().String())
	}
}

func pinned(srv *httptest.Server, pool *x509.CertPool, dialed *string) premisecheck.Client {
	return premisecheck.Client{Roots: pool, Lookup: publicLookup, Dial: dialTo(srv, dialed)}
}
