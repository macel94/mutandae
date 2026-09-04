package web

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mutandae/mutandae/internal/lifecycle"
	"github.com/mutandae/mutandae/pkg/protocol"
)

const (
	AuthModeNone  = "none"
	AuthModeOIDC  = "oidc"
	AuthModeToken = "token"

	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"

	sessionCookieName = "mutandae_session"
	oidcStateCookie   = "mutandae_oidc_state"
)

// APITokenConfig describes one already-hashed API token. Raw token material is
// accepted only through AuthConfig.APIToken and is immediately converted to a
// digest when the server is constructed.
type APITokenConfig struct {
	Name        string `json:"name"`
	TokenSHA256 string `json:"token_sha256"`
	Role        string `json:"role"`
}

// AuthConfig is the web authentication contract owned by the composition root.
// The web package never persists or logs APIToken. APITokensFile is reread for
// bearer requests, so removing or changing a digest revokes or changes access
// without a process restart.
type AuthConfig struct {
	Mode          string
	IssuerURL     string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	Scopes        string
	APIToken      string
	APITokens     []APITokenConfig
	APITokensFile string
	SessionKey    []byte
	SessionStore  SessionStore
	HTTPClient    *http.Client
}

// AuthMetadata is the safe authentication portion of the public configuration.
// It intentionally contains no issuer secret, client secret, token, digest, or
// session key.
type AuthMetadata struct {
	AuthMode         string   `json:"auth_mode"`
	Roles            []string `json:"roles"`
	TokensConfigured bool     `json:"tokens_configured"`
}

// AuthIdentity is the authenticated principal attached to a request.
type AuthIdentity struct {
	Principal string
	Subject   string
	Email     string
	Name      string
	Role      string
}

// Session is the server-side record represented by a signed session cookie.
type Session struct {
	Principal string
	Subject   string
	Email     string
	Name      string
	Role      string
	ExpiresAt time.Time
}

// SessionStore is deliberately small so deployments can replace the memory
// implementation with Redis without making handlers depend on a Redis client.
type SessionStore interface {
	Get(context.Context, string, time.Time) (Session, bool, error)
	Put(context.Context, string, Session) error
	Delete(context.Context, string) error
}

// MemorySessionStore is the default process-local session store. Expired
// records are removed during reads and writes, keeping memory bounded by live
// sessions in ordinary operation.
type MemorySessionStore struct {
	mu       sync.Mutex
	sessions map[string]Session
}

func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{sessions: make(map[string]Session)}
}

func (s *MemorySessionStore) Get(ctx context.Context, id string, now time.Time) (Session, bool, error) {
	if err := ctx.Err(); err != nil {
		return Session{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok {
		return Session{}, false, nil
	}
	if !session.ExpiresAt.After(now) {
		delete(s.sessions, id)
		return Session{}, false, nil
	}
	return session, true, nil
}

func (s *MemorySessionStore) Put(ctx context.Context, id string, session Session) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if id == "" || session.Role == "" || session.ExpiresAt.IsZero() {
		return errors.New("session id, role, and expiry are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions == nil {
		s.sessions = make(map[string]Session)
	}
	// Put has no clock argument, so it cannot safely decide which unrelated
	// records are expired. Reads perform precise expiry checks; retaining other
	// live sessions here avoids evicting users merely because a new session has
	// a later expiry.
	s.sessions[id] = session
	return nil
}

func (s *MemorySessionStore) Delete(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}

type authContextKey struct{}
type bearerContextKey struct{}

// IdentityFromContext returns the authenticated principal, if any.
func IdentityFromContext(ctx context.Context) (AuthIdentity, bool) {
	identity, ok := ctx.Value(authContextKey{}).(AuthIdentity)
	return identity, ok
}

// RoleFromContext returns the authenticated role or an empty string.
func RoleFromContext(ctx context.Context) string {
	identity, ok := IdentityFromContext(ctx)
	if !ok {
		return ""
	}
	return identity.Role
}

func bearerAuthenticated(r *http.Request) bool {
	value, _ := r.Context().Value(bearerContextKey{}).(bool)
	return value
}

func authMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return AuthModeNone
	}
	return mode
}

func validRole(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case RoleAdmin, RoleOperator, RoleViewer:
		return true
	default:
		return false
	}
}

func normalizeRole(role string) string {
	role = strings.ToLower(strings.TrimSpace(role))
	if validRole(role) {
		return role
	}
	return ""
}

func allRoles() []string {
	return []string{RoleAdmin, RoleOperator, RoleViewer}
}

// LoadAPITokensFile validates the public file format without retaining raw
// bearer credentials. Callers may retain the returned digests or just retain
// the file path for live revocation checks.
func LoadAPITokensFile(path string) ([]APITokenConfig, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("API tokens file path is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read API tokens file: %w", err)
	}
	var entries []APITokenConfig
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("decode API tokens file: %w", err)
	}
	return validateTokenEntries(entries)
}

func validateTokenEntries(entries []APITokenConfig) ([]APITokenConfig, error) {
	validated := make([]APITokenConfig, 0, len(entries))
	for index, entry := range entries {
		entry.Name = strings.TrimSpace(entry.Name)
		entry.TokenSHA256 = strings.ToLower(strings.TrimSpace(entry.TokenSHA256))
		entry.Role = normalizeRole(entry.Role)
		if entry.Name == "" {
			return nil, fmt.Errorf("API token %d has no name", index)
		}
		digest, err := hex.DecodeString(entry.TokenSHA256)
		if err != nil || len(digest) != sha256.Size {
			return nil, fmt.Errorf("API token %q has an invalid SHA-256 digest", entry.Name)
		}
		if entry.Role == "" {
			return nil, fmt.Errorf("API token %q has an invalid role", entry.Name)
		}
		validated = append(validated, entry)
	}
	return validated, nil
}

type tokenEntry struct {
	name   string
	digest []byte
	role   string
}

type authenticator struct {
	mode       string
	key        []byte
	sessions   SessionStore
	now        Clock
	client     *http.Client
	tokens     []tokenEntry
	tokenFile  string
	oidc       *oidcClient
	sessionTTL time.Duration
}

func newAuthenticator(cfg AuthConfig, now Clock) (*authenticator, error) {
	if now == nil {
		return nil, errors.New("auth clock is required")
	}
	mode := authMode(cfg.Mode)
	if mode != AuthModeNone && mode != AuthModeOIDC && mode != AuthModeToken {
		return nil, fmt.Errorf("unsupported auth mode %q", cfg.Mode)
	}
	a := &authenticator{
		mode:       mode,
		now:        now,
		client:     cfg.HTTPClient,
		sessions:   cfg.SessionStore,
		tokenFile:  strings.TrimSpace(cfg.APITokensFile),
		sessionTTL: 8 * time.Hour,
	}
	if a.client == nil {
		a.client = &http.Client{Timeout: 10 * time.Second}
	}
	if a.sessions == nil {
		a.sessions = NewMemorySessionStore()
	}
	if mode == AuthModeNone {
		return a, nil
	}
	if len(cfg.SessionKey) == 0 {
		key, err := randomBytes(32)
		if err != nil {
			return nil, fmt.Errorf("generate session signing key: %w", err)
		}
		cfg.SessionKey = key
	}
	if len(cfg.SessionKey) < 16 {
		return nil, errors.New("session signing key must contain at least 16 bytes")
	}
	a.key = append([]byte(nil), cfg.SessionKey...)
	entries, err := tokenEntries(cfg.APIToken, cfg.APITokens)
	if err != nil {
		return nil, err
	}
	// Keep only startup/static entries here. File-backed entries are loaded
	// afresh for each bearer request so changing a role or removing a digest
	// takes effect immediately instead of leaving the old entry authorized.
	a.tokens = entries
	var fileEntries []APITokenConfig
	if a.tokenFile != "" {
		fileEntries, err = LoadAPITokensFile(a.tokenFile)
		if err != nil {
			return nil, err
		}
	}
	if mode == AuthModeToken && len(a.tokens) == 0 && len(fileEntries) == 0 {
		return nil, errors.New("token auth mode requires at least one API token")
	}
	if mode == AuthModeOIDC {
		issuer := strings.TrimRight(strings.TrimSpace(cfg.IssuerURL), "/")
		if issuer == "" {
			return nil, errors.New("OIDC issuer URL is required")
		}
		parsed, err := url.Parse(issuer)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
			return nil, errors.New("OIDC issuer URL must be an absolute HTTP(S) URL without a path or query")
		}
		if strings.TrimSpace(cfg.ClientID) == "" {
			return nil, errors.New("OIDC client ID is required")
		}
		if strings.TrimSpace(cfg.ClientSecret) == "" {
			return nil, errors.New("OIDC client secret is required")
		}
		redirectURL := strings.TrimSpace(cfg.RedirectURL)
		if redirectURL != "" {
			parsedRedirect, redirectErr := url.Parse(redirectURL)
			if redirectErr != nil || parsedRedirect.Scheme == "" || parsedRedirect.Host == "" || (parsedRedirect.Scheme != "https" && parsedRedirect.Scheme != "http") {
				return nil, errors.New("OIDC redirect URL must be an absolute HTTP(S) URL")
			}
		}
		scopes := strings.TrimSpace(cfg.Scopes)
		if scopes == "" {
			scopes = "openid profile email"
		}
		a.oidc = &oidcClient{
			issuer:       issuer,
			clientID:     strings.TrimSpace(cfg.ClientID),
			clientSecret: cfg.ClientSecret,
			redirectURL:  redirectURL,
			scopes:       scopes,
			client:       a.client,
			now:          now,
		}
	}
	return a, nil
}

func tokenEntries(raw string, entries []APITokenConfig) ([]tokenEntry, error) {
	validated, err := validateTokenEntries(entries)
	if err != nil {
		return nil, err
	}
	out := makeTokenEntries(validated)
	if raw = strings.TrimSpace(raw); raw != "" {
		digest := sha256.Sum256([]byte(raw))
		out = append(out, tokenEntry{name: "env", digest: append([]byte(nil), digest[:]...), role: RoleAdmin})
	}
	return out, nil
}

func makeTokenEntries(entries []APITokenConfig) []tokenEntry {
	out := make([]tokenEntry, 0, len(entries))
	for _, entry := range entries {
		digest, err := hex.DecodeString(entry.TokenSHA256)
		if err != nil || len(digest) != sha256.Size {
			continue
		}
		out = append(out, tokenEntry{name: entry.Name, digest: digest, role: entry.Role})
	}
	return out
}

func (a *authenticator) metadata() AuthMetadata {
	if a == nil {
		return AuthMetadata{AuthMode: AuthModeNone, Roles: allRoles()}
	}
	return AuthMetadata{AuthMode: a.mode, Roles: allRoles(), TokensConfigured: len(a.tokens) > 0 || a.tokenFile != ""}
}

func (a *authenticator) tokenEntries() []tokenEntry {
	entries := append([]tokenEntry(nil), a.tokens...)
	if a.tokenFile == "" {
		return entries
	}
	// A readable file is authoritative for file-backed credentials. Do not
	// retain the previous file snapshot: an operator role change or removed
	// digest must revoke access on the next request. Static env/config entries
	// remain available independently.
	fileEntries, err := LoadAPITokensFile(a.tokenFile)
	if err != nil {
		return entries
	}
	return append(entries, makeTokenEntries(fileEntries)...)
}

func (a *authenticator) bearerIdentity(value string) (AuthIdentity, bool) {
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return AuthIdentity{}, false
	}
	digest := sha256.Sum256([]byte(parts[1]))
	matched := false
	role := ""
	principal := "api-token"
	for _, entry := range a.tokenEntries() {
		if len(entry.digest) != len(digest) {
			continue
		}
		match := subtle.ConstantTimeCompare(digest[:], entry.digest)
		if match == 1 && !matched {
			matched = true
			role = entry.role
			if entry.name != "" {
				principal = entry.name
			}
		}
	}
	if !matched {
		return AuthIdentity{}, false
	}
	return AuthIdentity{Principal: principal, Subject: principal, Name: principal, Role: role}, true
}

func (a *authenticator) ServeHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.publicRequest(r) || a.authRoute(r) {
			next.ServeHTTP(w, r)
			return
		}
		if value := r.Header.Get("Authorization"); value != "" {
			identity, ok := a.bearerIdentity(value)
			if !ok {
				a.unauthorized(w, r)
				return
			}
			ctx := context.WithValue(r.Context(), authContextKey{}, identity)
			ctx = context.WithValue(ctx, bearerContextKey{}, true)
			*r = *r.WithContext(ctx)
			a.authorize(w, r, next)
			return
		}
		if a.mode == AuthModeToken {
			a.unauthorized(w, r)
			return
		}
		identity, ok := a.sessionIdentity(r)
		if !ok {
			if isAPIRequest(r) {
				a.unauthorized(w, r)
				return
			}
			http.Redirect(w, r, "/auth/login?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		ctx := context.WithValue(r.Context(), authContextKey{}, identity)
		*r = *r.WithContext(ctx)
		a.authorize(w, r, next)
	})
}

func (a *authenticator) authorize(w http.ResponseWriter, r *http.Request, next http.Handler) {
	if !bearerAuthenticated(r) {
		csrf := csrfCookie(r)
		if csrf == "" {
			csrf = ensureCSRFCookie(w, r)
			r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrf})
		}
		if isMutation(r) {
			if err := validateCSRF(r, true); err != nil {
				a.forbidden(w, r, "csrf validation failed")
				return
			}
		}
	}
	required := requiredRole(r)
	if required != "" && !roleAllows(RoleFromContext(r.Context()), required) {
		a.forbidden(w, r, "insufficient role")
		return
	}
	next.ServeHTTP(w, r)
}

func (a *authenticator) publicRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	return r.URL.Path == "/livez" || r.URL.Path == "/readyz" || r.URL.Path == "/metrics" || strings.HasPrefix(r.URL.Path, "/static/") || r.URL.Path == "/favicon.ico" || r.URL.Path == "/favicon.svg"
}

func (a *authenticator) authRoute(r *http.Request) bool {
	return a.mode == AuthModeOIDC && (r.URL.Path == "/auth/login" || r.URL.Path == "/auth/callback" || r.URL.Path == "/auth/logout")
}

func isAPIRequest(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/api/")
}

func isMutation(r *http.Request) bool {
	return r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch || r.Method == http.MethodDelete
}

func requiredRole(r *http.Request) string {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return RoleViewer
	case http.MethodDelete:
		return RoleAdmin
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		if r.URL.Path == "/identities/provision" || r.URL.Path == "/api/v1/demo/identities" {
			return RoleAdmin
		}
		return RoleOperator
	default:
		return RoleOperator
	}
}

func roleAllows(actual, required string) bool {
	switch required {
	case RoleViewer:
		return validRole(actual)
	case RoleOperator:
		return actual == RoleOperator || actual == RoleAdmin
	case RoleAdmin:
		return actual == RoleAdmin
	default:
		return false
	}
}

func (a *authenticator) sessionIdentity(r *http.Request) (AuthIdentity, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return AuthIdentity{}, false
	}
	id, ok := verifySignedValue(cookie.Value, a.key)
	if !ok {
		return AuthIdentity{}, false
	}
	session, found, err := a.sessions.Get(r.Context(), id, a.now().UTC())
	if err != nil || !found || !validRole(session.Role) {
		return AuthIdentity{}, false
	}
	return AuthIdentity{Principal: session.Principal, Subject: session.Subject, Email: session.Email, Name: session.Name, Role: session.Role}, true
}

func (a *authenticator) unauthorized(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="mutandae"`)
	if isAPIRequest(r) || strings.Contains(strings.ToLower(r.Header.Get("Accept")), "json") {
		writeAuthJSON(w, http.StatusUnauthorized, "authentication_required", "authentication required")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(w, "authentication required\n")
}

func (a *authenticator) forbidden(w http.ResponseWriter, r *http.Request, message string) {
	if isAPIRequest(r) || strings.Contains(strings.ToLower(r.Header.Get("Accept")), "json") {
		writeAuthJSON(w, http.StatusForbidden, "forbidden", message)
		return
	}
	http.Error(w, message, http.StatusForbidden)
}

func writeAuthJSON(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", protocol.ContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	payload := struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{}
	payload.Error.Code = code
	payload.Error.Message = message
	_ = json.NewEncoder(w).Encode(payload)
}

func (a *authenticator) login(w http.ResponseWriter, r *http.Request) {
	if a.oidc == nil {
		http.Error(w, "OIDC is not configured", http.StatusNotImplemented)
		return
	}
	discovery, err := a.oidc.getDiscovery(r.Context(), false)
	if err != nil {
		http.Error(w, "OIDC discovery failed", http.StatusBadGateway)
		return
	}
	state, err := randomURLToken(32)
	if err != nil {
		http.Error(w, "unable to start login", http.StatusInternalServerError)
		return
	}
	nonce, err := randomURLToken(32)
	if err != nil {
		http.Error(w, "unable to start login", http.StatusInternalServerError)
		return
	}
	verifier, err := randomURLToken(48)
	if err != nil {
		http.Error(w, "unable to start login", http.StatusInternalServerError)
		return
	}
	returnTo := r.URL.Query().Get("return_to")
	if !strings.HasPrefix(returnTo, "/") || strings.HasPrefix(returnTo, "//") {
		returnTo = "/"
	}
	redirectURL := a.oidc.redirectURLFor(r)
	statePayload, err := json.Marshal(oidcState{
		State: state, Nonce: nonce, Verifier: verifier, ReturnTo: returnTo,
		RedirectURL: redirectURL, ExpiresAt: a.now().Add(10 * time.Minute),
	})
	if err != nil {
		http.Error(w, "unable to start login", http.StatusInternalServerError)
		return
	}
	cookieValue, err := signPayload(statePayload, a.key)
	if err != nil {
		http.Error(w, "unable to start login", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: cookieValue, Path: "/auth", HttpOnly: true, Secure: requestIsSecure(r), SameSite: http.SameSiteLaxMode, MaxAge: 600})
	hash := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {a.oidc.clientID},
		"redirect_uri":          {redirectURL},
		"scope":                 {a.oidc.scopes},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(hash[:])},
		"code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, discovery.AuthorizationEndpoint+"?"+query.Encode(), http.StatusFound)
}

type oidcState struct {
	State       string    `json:"state"`
	Nonce       string    `json:"nonce"`
	Verifier    string    `json:"verifier"`
	ReturnTo    string    `json:"return_to"`
	RedirectURL string    `json:"redirect_url"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (a *authenticator) callback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(oidcStateCookie)
	if err != nil || cookie.Value == "" {
		http.Error(w, "OIDC state is missing", http.StatusBadRequest)
		return
	}
	clearAuthCookie(w, r, oidcStateCookie, "/auth", true)
	payload, ok := verifyPayload(cookie.Value, a.key)
	if !ok {
		http.Error(w, "OIDC state is invalid", http.StatusBadRequest)
		return
	}
	var state oidcState
	if err := json.Unmarshal(payload, &state); err != nil || state.State == "" || state.Nonce == "" || state.Verifier == "" || state.RedirectURL == "" || !state.ExpiresAt.After(a.now()) {
		http.Error(w, "OIDC state has expired", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(state.State), []byte(r.URL.Query().Get("state"))) != 1 {
		http.Error(w, "OIDC state mismatch", http.StatusBadRequest)
		return
	}
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		http.Error(w, "OIDC authorization code is missing", http.StatusBadRequest)
		return
	}
	discovery, err := a.oidc.getDiscovery(r.Context(), false)
	if err != nil {
		http.Error(w, "OIDC discovery failed", http.StatusBadGateway)
		return
	}
	tokens, err := a.oidc.exchange(r.Context(), discovery, code, state.Verifier, state.RedirectURL)
	if err != nil {
		http.Error(w, "OIDC token exchange failed", http.StatusBadGateway)
		return
	}
	claims, err := a.oidc.verifyIDToken(r.Context(), discovery, tokens.IDToken, state.Nonce, a.now())
	if err != nil {
		http.Error(w, "OIDC identity verification failed", http.StatusUnauthorized)
		return
	}
	identity := claims.identity()
	sessionID, err := randomURLToken(32)
	if err != nil {
		http.Error(w, "unable to create session", http.StatusInternalServerError)
		return
	}
	expires := a.now().Add(a.sessionTTL)
	if err := a.sessions.Put(r.Context(), sessionID, Session{Principal: identity.Principal, Subject: identity.Subject, Email: identity.Email, Name: identity.Name, Role: identity.Role, ExpiresAt: expires}); err != nil {
		http.Error(w, "unable to create session", http.StatusInternalServerError)
		return
	}
	signed, err := signValue(sessionID, a.key)
	if err != nil {
		http.Error(w, "unable to create session", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: signed, Path: "/", HttpOnly: true, Secure: requestIsSecure(r), SameSite: http.SameSiteLaxMode, MaxAge: int(a.sessionTTL / time.Second)})
	returnTo := state.ReturnTo
	if !strings.HasPrefix(returnTo, "/") || strings.HasPrefix(returnTo, "//") {
		returnTo = "/"
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

type oidcTokens struct {
	IDToken string `json:"id_token"`
}

func (a *authenticator) logout(w http.ResponseWriter, r *http.Request) {
	if err := validateAuthCSRF(r); err != nil {
		if csrfCookie(r) == "" {
			csrf := ensureCSRFCookie(w, r)
			r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrf})
		}
		if err := validateAuthCSRF(r); err != nil {
			a.forbidden(w, r, "csrf validation failed")
			return
		}
	}
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		if id, ok := verifySignedValue(cookie.Value, a.key); ok {
			_ = a.sessions.Delete(r.Context(), id)
		}
	}
	clearAuthCookie(w, r, sessionCookieName, "/", true)
	http.Redirect(w, r, "/", http.StatusFound)
}

func signValue(value string, key []byte) (string, error) {
	return signPayload([]byte(value), key)
}

func signPayload(payload []byte, key []byte) (string, error) {
	if len(key) == 0 {
		return "", errors.New("signing key is empty")
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(encoded))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return encoded + "." + signature, nil
}

func verifySignedValue(value string, key []byte) (string, bool) {
	payload, ok := verifyPayload(value, key)
	if !ok {
		return "", false
	}
	return string(payload), true
}

func verifyPayload(value string, key []byte) ([]byte, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 || len(key) == 0 {
		return nil, false
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(parts[0]))
	expected, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || subtle.ConstantTimeCompare(expected, mac.Sum(nil)) != 1 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	return payload, err == nil
}

func clearAuthCookie(w http.ResponseWriter, r *http.Request, name, path string, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: path, HttpOnly: httpOnly, Secure: requestIsSecure(r), SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func randomBytes(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("random byte size must be positive")
	}
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	return value, nil
}

func randomURLToken(size int) (string, error) {
	value, err := randomBytes(size)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

// --- OIDC provider client ---

type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type oidcClient struct {
	issuer       string
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       string
	client       *http.Client
	now          Clock

	discoveryMu sync.Mutex
	discovery   oidcDiscovery
	discovered  time.Time
	jwksMu      sync.Mutex
	jwks        map[string]*rsa.PublicKey
	jwksFetched time.Time
}

func cacheFresh(now, fetched time.Time, ttl time.Duration) bool {
	if fetched.IsZero() || now.Before(fetched) {
		return false
	}
	return now.Sub(fetched) < ttl
}

func validateAuthCSRF(r *http.Request) error {
	if bearerAuthenticated(r) {
		return nil
	}
	cookie := csrfCookie(r)
	if cookie == "" {
		return lifecycle.ErrIntegrationCSRF
	}
	provided := r.Header.Get("X-Mutandae-CSRF")
	if provided == "" {
		provided = r.FormValue("csrf_token")
	}
	if !secureStringEqual(cookie, provided) {
		return lifecycle.ErrIntegrationCSRF
	}
	return nil
}

func (o *oidcClient) redirectURLFor(r *http.Request) string {
	if o.redirectURL != "" {
		return o.redirectURL
	}
	scheme := "http"
	if requestIsSecure(r) {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/auth/callback"
}

func (o *oidcClient) getDiscovery(ctx context.Context, force bool) (oidcDiscovery, error) {
	o.discoveryMu.Lock()
	if !force && o.discovery.AuthorizationEndpoint != "" && cacheFresh(o.now(), o.discovered, 10*time.Minute) {
		discovery := o.discovery
		o.discoveryMu.Unlock()
		return discovery, nil
	}
	o.discoveryMu.Unlock()
	endpoint := strings.TrimRight(o.issuer, "/") + "/.well-known/openid-configuration"
	var discovery oidcDiscovery
	if err := o.getJSON(ctx, endpoint, &discovery); err != nil {
		return oidcDiscovery{}, err
	}
	if strings.TrimRight(discovery.Issuer, "/") != o.issuer || discovery.AuthorizationEndpoint == "" || discovery.TokenEndpoint == "" || discovery.JWKSURI == "" {
		return oidcDiscovery{}, errors.New("OIDC discovery document is incomplete or has the wrong issuer")
	}
	for name, endpoint := range map[string]string{
		"authorization": discovery.AuthorizationEndpoint,
		"token":         discovery.TokenEndpoint,
		"JWKS":          discovery.JWKSURI,
	} {
		parsed, parseErr := url.Parse(endpoint)
		if parseErr != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
			return oidcDiscovery{}, fmt.Errorf("OIDC %s endpoint is not an absolute HTTP(S) URL", name)
		}
	}
	o.discoveryMu.Lock()
	o.discovery = discovery
	o.discovered = o.now()
	o.discoveryMu.Unlock()
	return discovery, nil
}

func (o *oidcClient) exchange(ctx context.Context, discovery oidcDiscovery, code, verifier, redirect string) (oidcTokens, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"client_id":     {o.clientID},
		"client_secret": {o.clientSecret},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, discovery.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return oidcTokens{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := o.client.Do(req)
	if err != nil {
		return oidcTokens{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return oidcTokens{}, fmt.Errorf("OIDC token endpoint returned %s", resp.Status)
	}
	var tokens oidcTokens
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tokens); err != nil {
		return oidcTokens{}, err
	}
	if tokens.IDToken == "" {
		return oidcTokens{}, errors.New("OIDC token response has no ID token")
	}
	return tokens, nil
}

func (o *oidcClient) getJSON(ctx context.Context, endpoint string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("OIDC endpoint returned %s", resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(target)
}

func (o *oidcClient) fetchJWKS(ctx context.Context, discovery oidcDiscovery, force bool) (map[string]*rsa.PublicKey, error) {
	o.jwksMu.Lock()
	if !force && len(o.jwks) > 0 && cacheFresh(o.now(), o.jwksFetched, 10*time.Minute) {
		keys := cloneKeys(o.jwks)
		o.jwksMu.Unlock()
		return keys, nil
	}
	o.jwksMu.Unlock()
	var document struct {
		Keys []struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := o.getJSON(ctx, discovery.JWKSURI, &document); err != nil {
		return nil, err
	}
	keys := make(map[string]*rsa.PublicKey, len(document.Keys))
	for _, key := range document.Keys {
		if key.Kty != "RSA" || key.Kid == "" || (key.Alg != "" && key.Alg != "RS256") || key.N == "" || key.E == "" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil || len(eBytes) == 0 || len(eBytes) > 4 {
			continue
		}
		e := 0
		for _, value := range eBytes {
			e = e<<8 | int(value)
		}
		if e < 2 {
			continue
		}
		keys[key.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
	}
	if len(keys) == 0 {
		return nil, errors.New("OIDC JWKS contains no RSA keys")
	}
	o.jwksMu.Lock()
	o.jwks = cloneKeys(keys)
	o.jwksFetched = o.now()
	o.jwksMu.Unlock()
	return keys, nil
}

func cloneKeys(input map[string]*rsa.PublicKey) map[string]*rsa.PublicKey {
	output := make(map[string]*rsa.PublicKey, len(input))
	for kid, key := range input {
		output[kid] = key
	}
	return output
}

type idTokenClaims struct {
	Issuer            string
	Audience          []string
	ExpiresAt         int64
	Nonce             string
	Subject           string
	Email             string
	Name              string
	PreferredUsername string
	Role              string
	Roles             []string
}

func (c idTokenClaims) identity() AuthIdentity {
	principal := c.Email
	if principal == "" {
		principal = c.PreferredUsername
	}
	if principal == "" {
		principal = c.Name
	}
	if principal == "" {
		principal = c.Subject
	}
	role := normalizeRole(c.Role)
	if role == "" {
		for _, candidate := range c.Roles {
			if normalized := normalizeRole(candidate); normalized != "" {
				if role == "" || normalized == RoleAdmin || (normalized == RoleOperator && role == RoleViewer) {
					role = normalized
				}
			}
		}
	}
	if role == "" {
		role = RoleViewer
	}
	return AuthIdentity{Principal: principal, Subject: c.Subject, Email: c.Email, Name: c.Name, Role: role}
}

func (o *oidcClient) verifyIDToken(ctx context.Context, discovery oidcDiscovery, token, expectedNonce string, now time.Time) (idTokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return idTokenClaims{}, errors.New("ID token is not a JWT")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(headerBytes, &header) != nil || header.Alg != "RS256" || header.Kid == "" {
		return idTokenClaims{}, errors.New("ID token has an unsupported header")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return idTokenClaims{}, errors.New("ID token payload is invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return idTokenClaims{}, errors.New("ID token signature is invalid")
	}
	keys, err := o.fetchJWKS(ctx, discovery, false)
	if err != nil {
		return idTokenClaims{}, err
	}
	key := keys[header.Kid]
	if key == nil {
		keys, err = o.fetchJWKS(ctx, discovery, true)
		if err != nil {
			return idTokenClaims{}, err
		}
		key = keys[header.Kid]
	}
	if key == nil {
		return idTokenClaims{}, errors.New("ID token signing key is unknown")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return idTokenClaims{}, errors.New("ID token signature is invalid")
	}
	var raw map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(payloadBytes)))
	decoder.UseNumber()
	if err := decoder.Decode(&raw); err != nil {
		return idTokenClaims{}, err
	}
	issuer, _ := raw["iss"].(string)
	if strings.TrimRight(issuer, "/") != o.issuer {
		return idTokenClaims{}, errors.New("ID token issuer is invalid")
	}
	audience := claimAudience(raw["aud"])
	foundAudience := false
	for _, candidate := range audience {
		if candidate == o.clientID {
			foundAudience = true
			break
		}
	}
	if !foundAudience {
		return idTokenClaims{}, errors.New("ID token audience is invalid")
	}
	exp, ok := claimInt64(raw["exp"])
	if !ok || !time.Unix(exp, 0).UTC().After(now.UTC()) {
		return idTokenClaims{}, errors.New("ID token is expired")
	}
	nonce, _ := raw["nonce"].(string)
	if subtle.ConstantTimeCompare([]byte(nonce), []byte(expectedNonce)) != 1 {
		return idTokenClaims{}, errors.New("ID token nonce is invalid")
	}
	subject, _ := raw["sub"].(string)
	if subject == "" {
		return idTokenClaims{}, errors.New("ID token subject is missing")
	}
	return idTokenClaims{
		Issuer: issuer, Audience: audience, ExpiresAt: exp, Nonce: nonce, Subject: subject,
		Email: stringClaim(raw, "email"), Name: stringClaim(raw, "name"), PreferredUsername: stringClaim(raw, "preferred_username"),
		Role: stringClaim(raw, "role"), Roles: stringSliceClaim(raw, "roles"),
	}, nil
}

func claimAudience(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}

func claimInt64(value any) (int64, bool) {
	switch typed := value.(type) {
	case json.Number:
		parsed, err := strconv.ParseInt(string(typed), 10, 64)
		return parsed, err == nil
	case float64:
		return int64(typed), typed == float64(int64(typed))
	default:
		return 0, false
	}
}

func stringClaim(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return strings.TrimSpace(value)
}

func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		http.Error(w, "authentication is not configured", http.StatusNotImplemented)
		return
	}
	s.auth.login(w, r)
}

func (s *Server) authCallback(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		http.Error(w, "authentication is not configured", http.StatusNotImplemented)
		return
	}
	s.auth.callback(w, r)
}

func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		http.Error(w, "authentication is not configured", http.StatusNotImplemented)
		return
	}
	s.auth.logout(w, r)
}

func stringSliceClaim(values map[string]any, key string) []string {
	value := values[key]
	if text, ok := value.(string); ok {
		return strings.Fields(text)
	}
	array, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(array))
	for _, item := range array {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}
