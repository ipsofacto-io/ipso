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
