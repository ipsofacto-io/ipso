package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso/internal/compiler/builtin"
	"github.com/ipsofacto-io/ipso/internal/premise"
	"github.com/ipsofacto-io/ipso/internal/premise/premisetest"
)

func TestPremiseCheckPassFailReport(t *testing.T) {
	const secret = "BODY-SECRET"
	const passBody = `{"major":16,"note":"` + secret + `"}`
	const failBody = `{"major":15,"note":"` + secret + `"}`
	var header http.Header
	mux := http.NewServeMux()
	mux.HandleFunc("/pass", func(w http.ResponseWriter, r *http.Request) {
		header = r.Header.Clone()
		_, _ = w.Write([]byte(passBody))
	})
	mux.HandleFunc("/fail", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(failBody))
	})
	client, _ := premiseHook(t, mux, []net.IP{net.ParseIP("1.1.1.1")}, nil)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	withDir(t, root)
	passFile := premiseFixture(idA, "postgres-major", "accepted", "2026-01-01", `
premises:
  - id: postgres-major-is-16
    statement: The platform still runs PostgreSQL 16.
    every: 1
    probe:
      url: https://example.com/pass
      pointer: /major
      equals: 16
`)
	failFile := premiseFixture(idB, "postgres-other", "accepted", "2026-01-01", `
premises:
  - id: postgres-major-is-16
    statement: The platform still runs PostgreSQL 16.
    every: 1
    probe:
      url: https://example.com/fail
      pointer: /major
      equals: 16
`)
	writeRepoFile(t, root, "docs/decisions/pass.md", passFile)
	writeRepoFile(t, root, "docs/decisions/fail.md", failFile)
	beforePass := readRepoFile(t, root, "docs/decisions/pass.md")
	beforeFail := readRepoFile(t, root, "docs/decisions/fail.md")
	report := filepath.Join(root, "out.json")
	stdout, stderr, code := premiseAt(t, now, client, []string{"--report", report})
	if code != 0 {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "docs/decisions/pass.md: postgres-major-is-16: pass") {
		t.Fatalf("stdout %s", stdout)
	}
	if !strings.Contains(stdout, "docs/decisions/fail.md: postgres-major-is-16: fail") {
		t.Fatalf("stdout %s", stdout)
	}
	if strings.Contains(stdout, secret) {
		t.Fatalf("stdout contains the body: %s", stdout)
	}
	if readRepoFile(t, root, "docs/decisions/pass.md") != beforePass || readRepoFile(t, root, "docs/decisions/fail.md") != beforeFail {
		t.Fatal("EDR bytes changed")
	}
	if _, err := os.Stat(filepath.Join(root, ".ipso", "build")); !os.IsNotExist(err) {
		t.Fatal("premise check wrote a build directory")
	}
	if header.Get("User-Agent") != premise.UserAgent || header.Get("Authorization") != "" || header.Get("Cookie") != "" {
		t.Fatalf("headers %#v", header)
	}
	raw := readRepoFile(t, root, "out.json")
	if strings.Contains(raw, secret) || strings.Contains(raw, passBody) || strings.Contains(raw, failBody) {
		t.Fatalf("report contains the body: %s", raw)
	}
	var decoded premiseReport
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ReportVersion != 1 || len(decoded.Premises) != 2 {
		t.Fatalf("report %+v", decoded)
	}
	byPath := map[string]premiseRow{}
	for _, row := range decoded.Premises {
		byPath[row.Path] = row
	}
	passRow := byPath["docs/decisions/pass.md"]
	if passRow.ID != "postgres-major-is-16" || passRow.DecisionID != idA || passRow.Result != "pass" || passRow.BodySHA256 != sha256Hex(passBody) {
		t.Fatalf("pass row %+v", passRow)
	}
	if string(passRow.Observed) != "16" || passRow.Expected != float64(16) {
		t.Fatalf("pass values expected %#v observed %s", passRow.Expected, passRow.Observed)
	}
	failRow := byPath["docs/decisions/fail.md"]
	if failRow.Result != "fail" || failRow.DecisionID != idB || string(failRow.Observed) != "15" || failRow.BodySHA256 != sha256Hex(failBody) {
		t.Fatalf("fail row %+v observed %s", failRow, failRow.Observed)
	}
}

func TestPremiseCheckErrors(t *testing.T) {
	hits := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/doc", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/secret", http.StatusFound)
	})
	mux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		hits++
	})
	mux.HandleFunc("/text", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-json-BODY"))
	})
	mux.HandleFunc("/missing", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"major":16}`))
	})
	mux.HandleFunc("/type", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"major":"16"}`))
	})
	dialed := 0
	client, _ := premiseHook(t, mux, nil, &dialed)
	client.Lookup = func(_ context.Context, host string) ([]net.IP, error) {
		if host == "private.example" {
			return []net.IP{net.ParseIP("10.1.2.3")}, nil
		}
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	withDir(t, root)
	writeRepoFile(t, root, "docs/decisions/private.md", premiseFixture(idA, "private-host", "accepted", "2026-01-01", `
premises:
  - id: private-host
    statement: The host must stay public.
    every: 1
    probe:
      url: https://private.example/doc
      pointer: /major
      equals: 16
`))
	writeRepoFile(t, root, "docs/decisions/redirect.md", premiseFixture(idB, "redirected", "needs-review", "2026-01-01", `
premises:
  - id: redirected
    statement: The document must not redirect.
    every: 1
    probe:
      url: https://example.com/doc
      pointer: /major
      equals: 16
`))
	writeRepoFile(t, root, "docs/decisions/text.md", premiseFixture(idC, "not-json", "accepted", "2026-01-01", `
premises:
  - id: not-json
    statement: The document must be JSON.
    every: 1
    probe:
      url: https://example.com/text
      pointer: /major
      equals: 16
  - id: missing-pointer
    statement: The pointer must exist.
    every: 1
    probe:
      url: https://example.com/missing
      pointer: /other
      equals: 16
  - id: wrong-type
    statement: The value must be a number.
    every: 1
    probe:
      url: https://example.com/type
      pointer: /major
      equals: 16
`))
	report := filepath.Join(root, "out.json")
	stdout, stderr, code := premiseAt(t, now, client, []string{"--report", report})
	if code != 1 {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	for _, line := range []string{
		"docs/decisions/private.md: private-host: error: private address",
		"docs/decisions/redirect.md: redirected: error: redirect",
		"docs/decisions/text.md: not-json: error: body is not json",
		"docs/decisions/text.md: missing-pointer: error: missing pointer",
		"docs/decisions/text.md: wrong-type: error: wrong type",
	} {
		if !strings.Contains(stdout, line) {
			t.Errorf("missing %s in %s", line, stdout)
		}
	}
	if hits != 0 {
		t.Fatalf("redirect was followed %d times", hits)
	}
	if strings.Contains(stdout, "not-json-BODY") {
		t.Fatal("stdout contains the body")
	}
	raw := readRepoFile(t, root, "out.json")
	if strings.Contains(raw, "not-json-BODY") {
		t.Fatal("report contains the body")
	}
	if !strings.Contains(raw, `"result": "error"`) || !strings.Contains(raw, `"id": "not-json"`) {
		t.Fatalf("report %s", raw)
	}
}

func TestPremiseCheckNoSelection(t *testing.T) {
	dialed := 0
	client, _ := premiseHook(t, http.NotFoundHandler(), []net.IP{net.ParseIP("1.1.1.1")}, &dialed)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	withDir(t, root)
	writeRepoFile(t, root, "docs/decisions/none.md", premiseFixture(idA, "no-premise", "accepted", "2026-01-01", ""))
	writeRepoFile(t, root, "docs/decisions/later.md", premiseFixture(idB, "later", "proposed", "2026-01-01", `
premises:
  - id: not-yet
    statement: This decision is not in force.
    every: 1
    probe:
      url: https://example.com/pass
      pointer: /major
      equals: 16
`))
	stdout, stderr, code := premiseAt(t, now, client, nil)
	if code != 0 {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	if strings.Contains(stdout, "not-yet") || dialed != 0 {
		t.Fatalf("stdout %s dialed %d", stdout, dialed)
	}
	if !strings.Contains(stdout, "docs/decisions/later.md: skipped, not in force") {
		t.Fatalf("stdout %s", stdout)
	}
}

func TestPremiseCheckUsage(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	d := deps{now: func() time.Time { return now }, registry: builtin.Registry()}
	cases := [][]string{
		{"premise"},
		{"premise", "fetch"},
		{"premise", "check", "extra"},
		{"premise", "check", "--report"},
		{"premise", "check", "--report", "--file"},
	}
	for _, args := range cases {
		var stdout, stderr bytes.Buffer
		code := run(args, &stdout, &stderr, d)
		if code != 2 || !strings.Contains(stderr.String(), premiseUsage) {
			t.Errorf("%v code %d stderr %s", args, code, stderr.String())
		}
	}
}

func TestPremiseCheckInvalidFileDoesNotProbe(t *testing.T) {
	dialed := 0
	client, _ := premiseHook(t, http.NotFoundHandler(), []net.IP{net.ParseIP("1.1.1.1")}, &dialed)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	withDir(t, root)
	writeRepoFile(t, root, "docs/decisions/bad.md", premiseFixture(idA, "duplicate", "accepted", "2026-01-01", `
premises:
  - id: same-id
    statement: One fact.
    every: 1
    probe:
      url: https://example.com/pass
      pointer: /major
      equals: 1
  - id: same-id
    statement: The same fact again.
    every: 1
    probe:
      url: https://example.com/pass
      pointer: /major
      equals: 1
`))
	report := filepath.Join(root, "out.json")
	stdout, stderr, code := premiseAt(t, now, client, []string{"--report", report})
	if code != 1 {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "duplicate premise id") || dialed != 0 {
		t.Fatalf("stdout %s dialed %d", stdout, dialed)
	}
	if _, err := os.Stat(report); !os.IsNotExist(err) {
		t.Fatal("report was written for an invalid file")
	}
}

func TestCompileIgnoresPremises(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	withDir(t, root)
	writeRepoFile(t, root, "docs/decisions/one.md", premiseFixture(idA, "with-premise", "accepted", "2026-01-01", `
premises:
  - id: postgres-major-is-16
    statement: The platform still runs PostgreSQL 16.
    every: 1
    probe:
      url: https://example.com/pass
      pointer: /major
      equals: 16
`))
	stdout, stderr, code := compileAt(t, now, builtin.Registry())
	if code != 0 {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
}

func premiseAt(t *testing.T, now time.Time, client premise.Client, args []string) (string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := append([]string{"premise", "check"}, args...)
	code := run(cmd, &stdout, &stderr, deps{
		now:         func() time.Time { return now },
		registry:    builtin.Registry(),
		probeClient: client,
	})
	return stdout.String(), stderr.String(), code
}

func premiseFixture(id, slug, status, from, premises string) string {
	record := compileRecord(id, slug, status, "warning", from, "", "")
	if strings.TrimSpace(premises) == "" {
		return record
	}
	if !strings.HasSuffix(premises, "\n") {
		premises += "\n"
	}
	return strings.Replace(record, "tags: [fixture]\n", "tags: [fixture]\n"+premises, 1)
}

func readRepoFile(t *testing.T, root, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func sha256Hex(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

func premiseHook(t *testing.T, handler http.Handler, ips []net.IP, dialed *int) (premise.Client, *httptest.Server) {
	t.Helper()
	srv, pool := premisetest.Server(t, "example.com", handler)
	if ips == nil {
		ips = []net.IP{net.ParseIP("1.1.1.1")}
	}
	client := premise.Client{
		Roots: pool,
		Lookup: func(context.Context, string) ([]net.IP, error) {
			return ips, nil
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if dialed != nil {
				*dialed++
			}
			var d net.Dialer
			return d.DialContext(ctx, network, srv.Listener.Addr().String())
		},
	}
	return client, srv
}
