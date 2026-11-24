// Package auth implements loopback PKCE CLI authentication, OS credential storage,
// and authenticated HTTP requests against an ipso-server control plane (ADR-0160).
package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	serviceName        = "ipso-cli"
	EnvToken           = "IPSO_TOKEN"
	EnvServerURL       = "IPSO_SERVER_URL"
	maxResponseBytes   = 4 << 20
	defaultHTTPTimeout = 30 * time.Second
)

// Session holds the resolved server URL and bearer token for one CLI call.
type Session struct {
	ServerURL string
	Token     string
}

// Store persists CLI bearer tokens per server URL in the OS credential store.
type Store interface {
	Save(serverURL, token string) error
	Load(serverURL string) (string, error)
	Delete(serverURL string) error
	DefaultServer() (string, error)
	SetDefaultServer(serverURL string) error
}

// MemoryStore is an in-memory Store used by unit tests.
type MemoryStore struct {
	Tokens map[string]string
	Server string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{Tokens: map[string]string{}}
}

func (m *MemoryStore) Save(serverURL, token string) error {
	m.Tokens[serverURL] = token
	m.Server = serverURL
	return nil
}

func (m *MemoryStore) Load(serverURL string) (string, error) {
	tok, ok := m.Tokens[serverURL]
	if !ok || tok == "" {
		return "", ErrNotLoggedIn
	}
	return tok, nil
}

func (m *MemoryStore) Delete(serverURL string) error {
	delete(m.Tokens, serverURL)
	return nil
}

func (m *MemoryStore) DefaultServer() (string, error) {
	if m.Server == "" {
		return "", ErrNotLoggedIn
	}
	return m.Server, nil
}

func (m *MemoryStore) SetDefaultServer(serverURL string) error {
	m.Server = serverURL
	return nil
}

// ErrNotLoggedIn reports that no token is configured via IPSO_TOKEN or the credential store.
var ErrNotLoggedIn = errors.New("not logged in; run `ipso login --server <url>` or set IPSO_TOKEN")

// NormalizeServerURL validates and canonicalizes a control-plane base URL.
// HTTPS is required except for loopback addresses (127.0.0.1, ::1, localhost).
func NormalizeServerURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("server URL is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("invalid server URL %q", raw)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("server URL %q must not contain credentials, query, or fragment", raw)
	}
	host := parsed.Hostname()
	switch parsed.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(host) {
			return "", fmt.Errorf("server URL %q must use https unless targeting loopback", raw)
		}
	default:
		return "", fmt.Errorf("server URL %q must use https", raw)
	}
	cleanPath := strings.TrimRight(parsed.Path, "/")
	return parsed.Scheme + "://" + parsed.Host + cleanPath, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Resolve resolves the active Session from explicit serverFlag, IPSO_SERVER_URL / IPSO_TOKEN, or store.
// When IPSO_TOKEN is set, the target server must match IPSO_SERVER_URL (or the saved login server when
// IPSO_SERVER_URL is unset) so an untrusted or mistyped --server never receives the bearer token.
func Resolve(store Store, serverFlag string) (Session, error) {
	if store == nil {
		store = DefaultStore()
	}
	flagRaw := strings.TrimSpace(serverFlag)
	envRaw := strings.TrimSpace(os.Getenv(EnvServerURL))
	if envTok := strings.TrimSpace(os.Getenv(EnvToken)); envTok != "" {
		boundRaw := envRaw
		if boundRaw == "" {
			if saved, err := store.DefaultServer(); err == nil {
				boundRaw = strings.TrimSpace(saved)
			}
		}
		if boundRaw == "" {
			return Session{}, errors.New("IPSO_TOKEN requires IPSO_SERVER_URL or a saved `ipso login` default server")
		}
		boundURL, err := NormalizeServerURL(boundRaw)
		if err != nil {
			return Session{}, err
		}
		if flagRaw != "" {
			flagURL, err := NormalizeServerURL(flagRaw)
			if err != nil {
				return Session{}, err
			}
			if flagURL != boundURL {
				return Session{}, fmt.Errorf("refusing to send IPSO_TOKEN to %s (bound to %s)", flagURL, boundURL)
			}
		}
		return Session{ServerURL: boundURL, Token: envTok}, nil
	}

	rawServer := flagRaw
	if rawServer == "" {
		rawServer = envRaw
	}
	if rawServer == "" {
		var err error
		rawServer, err = store.DefaultServer()
		if err != nil {
			return Session{}, ErrNotLoggedIn
		}
	}
	serverURL, err := NormalizeServerURL(rawServer)
	if err != nil {
		return Session{}, err
	}
	tok, err := store.Load(serverURL)
	if err != nil || strings.TrimSpace(tok) == "" {
		return Session{}, ErrNotLoggedIn
	}
	return Session{ServerURL: serverURL, Token: strings.TrimSpace(tok)}, nil
}

// PKCE holds a single-use S256 verifier, challenge, and anti-CSRF state.
type PKCE struct {
	Verifier  string
	Challenge string
	State     string
}

// GeneratePKCE creates a 32-byte random verifier, its S256 challenge, and a 16-byte random state.
func GeneratePKCE() (PKCE, error) {
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return PKCE{}, err
	}
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return PKCE{}, err
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := base64.RawURLEncoding.EncodeToString(stateBytes)
	return PKCE{Verifier: verifier, Challenge: challenge, State: state}, nil
}

// LoginOptions configures one interactive loopback PKCE sign-in.
type LoginOptions struct {
	ServerURL   string
	Store       Store
	HTTPClient  *http.Client
	OpenBrowser func(authURL string) error
	OnAuthURL   func(authURL string)
}

// TokenResponse is returned by POST /auth/cli/token on ipso-server.
type TokenResponse struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
	TenantSlug  string    `json:"tenant_slug,omitempty"`
}

// Login runs the loopback 127.0.0.1 PKCE S256 sign-in flow and saves the resulting CLI token in opts.Store.
func Login(ctx context.Context, opts LoginOptions) (TokenResponse, error) {
	serverURL, err := NormalizeServerURL(opts.ServerURL)
	if err != nil {
		return TokenResponse{}, err
	}
	store := opts.Store
	if store == nil {
		store = DefaultStore()
	}
	pkce, err := GeneratePKCE()
	if err != nil {
		return TokenResponse{}, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return TokenResponse{}, fmt.Errorf("listen loopback callback: %w", err)
	}
	defer func() { _ = ln.Close() }()

	redirectURI := fmt.Sprintf("http://%s/callback", ln.Addr().String())
	q := url.Values{}
	q.Set("redirect_uri", redirectURI)
	q.Set("code_challenge", pkce.Challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", pkce.State)
	authURL := serverURL + "/auth/cli/start?" + q.Encode()

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}

	type callbackResult struct {
		tok TokenResponse
		err error
	}
	resCh := make(chan callbackResult, 1)
	var cbMu sync.Mutex
	handled := false
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		gotState := r.URL.Query().Get("state")
		if len(gotState) != len(pkce.State) || subtle.ConstantTimeCompare([]byte(gotState), []byte(pkce.State)) != 1 {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		cbMu.Lock()
		if handled {
			cbMu.Unlock()
			http.Error(w, "callback already processed", http.StatusConflict)
			return
		}
		handled = true
		cbMu.Unlock()

		if errParam := r.URL.Query().Get("error"); errParam != "" {
			http.Error(w, "authentication failed", http.StatusBadRequest)
			resCh <- callbackResult{err: fmt.Errorf("authentication refused: %s", errParam)}
			return
		}
		code := strings.TrimSpace(r.URL.Query().Get("code"))
		if code == "" {
			http.Error(w, "missing authorization code", http.StatusBadRequest)
			resCh <- callbackResult{err: errors.New("missing authorization code on callback")}
			return
		}

		tok, exchErr := exchangeAndSaveCLIToken(ctx, client, store, serverURL, redirectURI, code, pkce.Verifier)
		if exchErr != nil {
			http.Error(w, "ipso CLI token exchange failed. Check your terminal for details.", http.StatusBadGateway)
			resCh <- callbackResult{err: exchErr}
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ipso CLI login succeeded. You may close this window.\n")
		resCh <- callbackResult{tok: tok}
	})
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	if opts.OnAuthURL != nil {
		opts.OnAuthURL(authURL)
	}
	if opts.OpenBrowser != nil {
		_ = opts.OpenBrowser(authURL)
	}

	select {
	case <-ctx.Done():
		return TokenResponse{}, ctx.Err()
	case cb := <-resCh:
		if cb.err != nil {
			return TokenResponse{}, cb.err
		}
		return cb.tok, nil
	}
}

func exchangeAndSaveCLIToken(ctx context.Context, client *http.Client, store Store, serverURL, redirectURI, code, verifier string) (TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", redirectURI)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/auth/cli/token", strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return TokenResponse{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return TokenResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return TokenResponse{}, decodeAPIError(resp.StatusCode, raw)
	}
	var tok TokenResponse
	if err := json.Unmarshal(raw, &tok); err != nil {
		return TokenResponse{}, fmt.Errorf("decode token response: %w", err)
	}
	if strings.TrimSpace(tok.AccessToken) == "" {
		return TokenResponse{}, errors.New("server returned an empty access_token")
	}
	if err := store.Save(serverURL, tok.AccessToken); err != nil {
		return TokenResponse{}, err
	}
	if err := store.SetDefaultServer(serverURL); err != nil {
		return TokenResponse{}, err
	}
	return tok, nil
}

// Logout deletes the local credential and revokes the CLI session on the server, returning an error if either step fails.
func Logout(ctx context.Context, store Store, client *http.Client, serverFlag string) error {
	if store == nil {
		store = DefaultStore()
	}
	sess, err := Resolve(store, serverFlag)
	if err != nil {
		return err
	}
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	var revokeErr error
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, sess.ServerURL+"/auth/cli/logout", bytes.NewReader([]byte(`{}`)))
	if reqErr != nil {
		revokeErr = reqErr
	} else {
		req.Header.Set("Authorization", "Bearer "+sess.Token)
		req.Header.Set("Content-Type", "application/json")
		resp, doErr := client.Do(req)
		if doErr != nil {
			revokeErr = doErr
		} else {
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
			_ = resp.Body.Close()
			if resp.StatusCode >= 400 {
				revokeErr = decodeAPIError(resp.StatusCode, raw)
			}
		}
	}
	delErr := store.Delete(sess.ServerURL)
	if delErr != nil {
		return delErr
	}
	if revokeErr != nil {
		return fmt.Errorf("local credential removed, but server session revocation failed: %w", revokeErr)
	}
	return nil
}

// Client performs authenticated JSON calls against ipso-server.
type Client struct {
	Session    Session
	HTTPClient *http.Client
}

func (c Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: defaultHTTPTimeout}
}

// GetJSON sends an authenticated GET request to pathAndQuery and decodes JSON into out.
func (c Client) GetJSON(ctx context.Context, pathAndQuery string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Session.ServerURL+pathAndQuery, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if c.Session.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Session.Token)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxResponseBytes {
		return fmt.Errorf("response exceeds %d bytes", maxResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decodeAPIError(resp.StatusCode, raw)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// GetRaw sends an authenticated GET request and returns the raw response bytes.
func (c Client) GetRaw(ctx context.Context, pathAndQuery string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Session.ServerURL+pathAndQuery, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.Session.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Session.Token)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxResponseBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", maxResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, decodeAPIError(resp.StatusCode, raw)
	}
	return raw, nil
}

// PostJSON sends an authenticated POST request with JSON body in and decodes JSON into out.
func (c Client) PostJSON(ctx context.Context, pathAndQuery string, in any, out any) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Session.ServerURL+pathAndQuery, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.Session.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Session.Token)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxResponseBytes {
		return fmt.Errorf("response exceeds %d bytes", maxResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decodeAPIError(resp.StatusCode, raw)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func decodeAPIError(status int, raw []byte) error {
	var prob struct {
		Title  string `json:"title"`
		Detail string `json:"detail"`
	}
	if json.Unmarshal(raw, &prob) == nil {
		switch {
		case prob.Title != "" && prob.Detail != "":
			return fmt.Errorf("HTTP %d %s: %s", status, prob.Title, prob.Detail)
		case prob.Detail != "":
			return fmt.Errorf("HTTP %d: %s", status, prob.Detail)
		case prob.Title != "":
			return fmt.Errorf("HTTP %d: %s", status, prob.Title)
		}
	}
	return fmt.Errorf("HTTP %d", status)
}

// DefaultStore returns the native OS credential store (macOS Keychain via /usr/bin/security,
// Linux libsecret via secret-tool) paired with non-secret server selection metadata under UserConfigDir.
func DefaultStore() Store {
	return osStore{}
}

type osStore struct{}

func configFilePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ipso", "cli.json"), nil
}

type cliMeta struct {
	DefaultServer string `json:"default_server"`
}

func (osStore) DefaultServer() (string, error) {
	p, err := configFilePath()
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return "", ErrNotLoggedIn
	}
	var m cliMeta
	if err := json.Unmarshal(raw, &m); err != nil || m.DefaultServer == "" {
		return "", ErrNotLoggedIn
	}
	return m.DefaultServer, nil
}

func (osStore) SetDefaultServer(serverURL string) error {
	p, err := configFilePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cliMeta{DefaultServer: serverURL}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, raw, 0o600)
}

func validKeychainAtom(s string) bool {
	return s != "" && !strings.ContainsAny(s, "\"'\\\r\n\x00 \t")
}

func (osStore) Save(serverURL, token string) error {
	if !validKeychainAtom(serverURL) || !validKeychainAtom(token) {
		return errors.New("refusing credential with unsafe characters")
	}
	switch runtime.GOOS {
	case "darwin":
		// Use `security -i` over stdin so the bearer token never appears in process argv (CWE-214).
		cmd := exec.Command("/usr/bin/security", "-i")
		cmd.Stdin = strings.NewReader(fmt.Sprintf("add-generic-password -U -s %q -a %q -w %q\n", serviceName, serverURL, token))
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("keychain save failed: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	case "linux":
		path, err := exec.LookPath("secret-tool")
		if err != nil {
			return errors.New("secret-tool not found; install libsecret-tools or pass IPSO_TOKEN")
		}
		cmd := exec.Command(path, "store", "--label=ipso-cli", "service", serviceName, "server", serverURL)
		cmd.Stdin = strings.NewReader(token)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("secret-tool store failed: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	default:
		return errors.New("native credential store unsupported on this OS; use IPSO_TOKEN")
	}
}

func (osStore) Load(serverURL string) (string, error) {
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("/usr/bin/security", "find-generic-password", "-s", serviceName, "-a", serverURL, "-w")
		out, err := cmd.Output()
		if err != nil {
			return "", ErrNotLoggedIn
		}
		return strings.TrimSpace(string(out)), nil
	case "linux":
		path, err := exec.LookPath("secret-tool")
		if err != nil {
			return "", ErrNotLoggedIn
		}
		cmd := exec.Command(path, "lookup", "service", serviceName, "server", serverURL)
		out, err := cmd.Output()
		if err != nil {
			return "", ErrNotLoggedIn
		}
		return strings.TrimSpace(string(out)), nil
	default:
		return "", ErrNotLoggedIn
	}
}

func (osStore) Delete(serverURL string) error {
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("/usr/bin/security", "delete-generic-password", "-s", serviceName, "-a", serverURL)
		_ = cmd.Run()
		return nil
	case "linux":
		if path, err := exec.LookPath("secret-tool"); err == nil {
			cmd := exec.Command(path, "clear", "service", serviceName, "server", serverURL)
			_ = cmd.Run()
		}
		return nil
	default:
		return nil
	}
}

// OpenSystemBrowser launches url in the user's default browser when interactive.
func OpenSystemBrowser(targetURL string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("/usr/bin/open", targetURL).Start()
	case "linux":
		if p, err := exec.LookPath("xdg-open"); err == nil {
			return exec.Command(p, targetURL).Start()
		}
	}
	return nil
}
