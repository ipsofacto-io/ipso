package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestLoginLoopbackPKCEAndLogout(t *testing.T) {
	var seenChallenge string
	revoked := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/cli/start":
			seenChallenge = r.URL.Query().Get("code_challenge")
			if r.URL.Query().Get("code_challenge_method") != "S256" {
				t.Errorf("challenge method = %q", r.URL.Query().Get("code_challenge_method"))
			}
			redirectURI := r.URL.Query().Get("redirect_uri")
			state := r.URL.Query().Get("state")
			http.Redirect(w, r, redirectURI+"?code=authcode-123&state="+url.QueryEscape(state), http.StatusFound)
		case "/auth/cli/token":
			if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
				t.Fatalf("Content-Type = %q, want application/x-www-form-urlencoded", got)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Form.Get("grant_type") != "authorization_code" {
				t.Fatalf("grant_type = %q", r.Form.Get("grant_type"))
			}
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != seenChallenge {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(TokenResponse{
				AccessToken: "ipsocli_abcdefghijklmnopqrstuvwxyz123456",
				ExpiresAt:   time.Date(2026, 12, 24, 15, 0, 0, 0, time.UTC),
				TenantSlug:  "acme",
			})
		case "/auth/cli/logout":
			if r.Header.Get("Authorization") == "Bearer ipsocli_abcdefghijklmnopqrstuvwxyz123456" {
				revoked = true
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	store := NewMemoryStore()
	tok, err := Login(context.Background(), LoginOptions{
		ServerURL:  srv.URL,
		Store:      store,
		HTTPClient: srv.Client(),
		OpenBrowser: func(authURL string) error {
			resp, err := srv.Client().Get(authURL)
			if err != nil {
				return err
			}
			_ = resp.Body.Close()
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatal("empty access token")
	}

	sess, err := Resolve(store, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if sess.Token != tok.AccessToken || sess.ServerURL != srv.URL {
		t.Fatalf("sess = %+v", sess)
	}

	if err := Logout(context.Background(), store, srv.Client(), ""); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if !revoked {
		t.Fatal("expected server /auth/cli/logout to receive bearer token")
	}
	if _, err := Resolve(store, ""); err == nil {
		t.Fatal("expected ErrNotLoggedIn after Logout")
	}
}

func TestNormalizeServerURLRefusesPlainHTTPNonLoopback(t *testing.T) {
	if _, err := NormalizeServerURL("http://api.ipsoplatform.io"); err == nil {
		t.Fatal("expected plain HTTP remote server URL to be refused")
	}
	got, err := NormalizeServerURL("https://api.ipsoplatform.io/")
	if err != nil || got != "https://api.ipsoplatform.io" {
		t.Fatalf("got %q, err %v", got, err)
	}
	if _, err := NormalizeServerURL("http://127.0.0.1:8080"); err != nil {
		t.Fatalf("loopback HTTP refused: %v", err)
	}
}

func TestResolveBindsEnvTokenToConfiguredServer(t *testing.T) {
	t.Setenv(EnvToken, "ipsocli_abcdefghijklmnopqrstuvwxyz123456")
	t.Setenv(EnvServerURL, "https://ipso.acme.io")
	store := NewMemoryStore()

	sess, err := Resolve(store, "")
	if err != nil || sess.ServerURL != "https://ipso.acme.io" {
		t.Fatalf("Resolve = %+v, err = %v", sess, err)
	}
	if _, err := Resolve(store, "https://evil.example.com"); err == nil {
		t.Fatal("expected mismatched --server to be refused when IPSO_TOKEN is set")
	}

	t.Setenv(EnvServerURL, "")
	if _, err := Resolve(store, "https://evil.example.com"); err == nil {
		t.Fatal("expected unbound IPSO_TOKEN without IPSO_SERVER_URL or saved server to be refused")
	}
}

func TestLoginCallbackReportsFailureWhenTokenExchangeFails(t *testing.T) {
	var browserStatus int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/cli/start":
			redirectURI := r.URL.Query().Get("redirect_uri")
			state := r.URL.Query().Get("state")
			http.Redirect(w, r, redirectURI+"?code=authcode-fail&state="+url.QueryEscape(state), http.StatusFound)
		case "/auth/cli/token":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"title":"invalid_login"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	_, err := Login(context.Background(), LoginOptions{
		ServerURL:  srv.URL,
		Store:      NewMemoryStore(),
		HTTPClient: srv.Client(),
		OpenBrowser: func(authURL string) error {
			resp, err := srv.Client().Get(authURL)
			if err != nil {
				return err
			}
			browserStatus = resp.StatusCode
			_ = resp.Body.Close()
			return nil
		},
	})
	if err == nil {
		t.Fatal("expected Login to fail when token exchange fails")
	}
	if browserStatus != http.StatusBadGateway {
		t.Fatalf("browser callback status = %d, want %d", browserStatus, http.StatusBadGateway)
	}
}

func TestLoginCallbackFailsFastOnMalformedState(t *testing.T) {
	var callbackStatus int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/cli/start" {
			redirectURI := r.URL.Query().Get("redirect_uri")
			http.Redirect(w, r, redirectURI+"?code=fake&state=short", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := Login(ctx, LoginOptions{
		ServerURL:  srv.URL,
		Store:      NewMemoryStore(),
		HTTPClient: srv.Client(),
		OpenBrowser: func(authURL string) error {
			resp, err := srv.Client().Get(authURL)
			if err != nil {
				return err
			}
			callbackStatus = resp.StatusCode
			_ = resp.Body.Close()
			return nil
		},
	})
	if err == nil {
		t.Fatal("expected Login to fail fast on wrong-length state")
	}
	if callbackStatus != http.StatusBadRequest {
		t.Fatalf("callback status = %d, want 400", callbackStatus)
	}
}

func TestLogoutRetainsCredentialOnServerFailureAndDeletesOnceRevoked(t *testing.T) {
	status := http.StatusServiceUnavailable
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if status >= 500 {
			_, _ = w.Write([]byte(`{"title":"unavailable"}`))
		}
	}))
	defer srv.Close()

	store := NewMemoryStore()
	if err := store.Save(srv.URL, "ipsocli_abcdefghijklmnopqrstuvwxyz123456"); err != nil {
		t.Fatal(err)
	}
	if err := Logout(context.Background(), store, srv.Client(), ""); err == nil {
		t.Fatal("expected Logout to report server-side revocation failure")
	}
	if _, resolveErr := Resolve(store, ""); resolveErr != nil {
		t.Fatalf("expected local credential to remain so user can retry logout, got %v", resolveErr)
	}

	status = http.StatusUnauthorized
	if err := Logout(context.Background(), store, srv.Client(), ""); err != nil {
		t.Fatalf("expected Logout to succeed when server reports session already invalid (401): %v", err)
	}
	if _, resolveErr := Resolve(store, ""); resolveErr == nil {
		t.Fatal("expected local credential to be deleted once server reports 401")
	}
}

func TestClientRefusesRedirects(t *testing.T) {
	leaked := false
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = true
		w.WriteHeader(http.StatusOK)
	}))
	defer evil.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	c := Client{
		Session:    Session{ServerURL: origin.URL, Token: "ipsocli_abcdefghijklmnopqrstuvwxyz123456"},
		HTTPClient: origin.Client(),
	}
	var out map[string]any
	if err := c.PostJSON(context.Background(), "/v1/verifiability", map[string]string{"title": "t"}, &out); err == nil {
		t.Fatal("expected redirect on ipso-server API call to be refused")
	}
	if leaked {
		t.Fatal("redirect target must never receive request")
	}
}
