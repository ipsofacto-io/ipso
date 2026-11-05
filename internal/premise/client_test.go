package premise

import (
	"bytes"
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ipsofacto-io/ipso/internal/premise/premisetest"
)

func TestCheckRefusesPrivateAddress(t *testing.T) {
	dialed := false
	client := Client{
		Lookup: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("1.1.1.1")}, nil
		},
		Dial: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, context.Canceled
		},
	}
	got := client.Check(context.Background(), Spec{
		URL: "https://example.com/a.json", Pointer: "/a", Equals: float64(1), HasEquals: true,
	})
	if got.Result != ResultError || got.Reason != ReasonPrivate || got.BodySHA256 != "" || dialed {
		t.Fatalf("result %+v dialed %v", got, dialed)
	}
}

func TestCheckPinsTheDialAndSendsNoCredentials(t *testing.T) {
	const body = `{"major":16,"secret":"BODY-SECRET"}`
	var header http.Header
	srv, pool := premisetest.Server(t, "example.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header = r.Header.Clone()
		_, _ = w.Write([]byte(body))
	}))
	dialed := ""
	client := Client{
		Roots: pool,
		Lookup: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed = addr
			var d net.Dialer
			return d.DialContext(ctx, network, srv.Listener.Addr().String())
		},
	}
	got := client.Check(context.Background(), Spec{
		URL: "https://example.com/platform/postgres.json", Pointer: "/major", Equals: float64(16), HasEquals: true,
	})
	if got.Result != ResultPass || string(got.Observed) != "16" {
		t.Fatalf("result %+v observed %s", got, got.Observed)
	}
	if dialed != "1.1.1.1:443" {
		t.Fatalf("dialed %s", dialed)
	}
	if header.Get("User-Agent") != UserAgent || header.Get("Authorization") != "" || header.Get("Cookie") != "" {
		t.Fatalf("headers %#v", header)
	}
	if got.BodySHA256 != hashBytes([]byte(body)) {
		t.Fatalf("hash %s", got.BodySHA256)
	}
}

func TestCheckRedirectDoesNotFollow(t *testing.T) {
	hits := 0
	srv, pool := premisetest.Server(t, "example.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/secret" {
			hits++
			_, _ = w.Write([]byte("secret-body"))
			return
		}
		http.Redirect(w, r, "https://example.com/secret", http.StatusFound)
	}))
	client := pinnedClient(srv, pool)
	got := client.Check(context.Background(), Spec{
		URL: "https://example.com/a.json", Pointer: "/a", Equals: float64(1), HasEquals: true,
	})
	if got.Result != ResultError || got.Reason != ReasonRedirect || hits != 0 || got.Observed != nil {
		t.Fatalf("result %+v hits %d", got, hits)
	}
}

func TestCheckNonJSON(t *testing.T) {
	srv, pool := premisetest.Server(t, "example.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-json-BODY"))
	}))
	got := pinnedClient(srv, pool).Check(context.Background(), Spec{
		URL: "https://example.com/a.json", Pointer: "/a", Equals: float64(1), HasEquals: true,
	})
	if got.Result != ResultError || got.Reason != ReasonNotJSON || got.Observed != nil {
		t.Fatalf("result %+v", got)
	}
	if got.BodySHA256 != hashBytes([]byte("not-json-BODY")) {
		t.Fatalf("hash %s", got.BodySHA256)
	}
}

func TestCheckBodyTooLarge(t *testing.T) {
	payload := bytes.Repeat([]byte("a"), BodyLimit+1)
	srv, pool := premisetest.Server(t, "example.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for range payload {
			_, _ = w.Write([]byte("a"))
		}
	}))
	got := pinnedClient(srv, pool).Check(context.Background(), Spec{
		URL: "https://example.com/a.json", Pointer: "", Equals: "a", HasEquals: true,
	})
	if got.Result != ResultError || got.Reason != ReasonBody || got.Observed != nil {
		t.Fatalf("result %+v", got)
	}
	if got.BodySHA256 != hashBytes(payload[:BodyLimit]) {
		t.Fatalf("hash %s", got.BodySHA256)
	}
}

func pinnedClient(srv *httptest.Server, pool *x509.CertPool) Client {
	return Client{
		Roots: pool,
		Lookup: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, srv.Listener.Addr().String())
		},
	}
}
