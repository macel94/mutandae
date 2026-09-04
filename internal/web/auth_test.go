package web

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func tokenRequest(t *testing.T, handler http.Handler, method, path, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func TestTokenAuthAndRBAC(t *testing.T) {
	store := testStore(t)
	adminServer, err := NewServer(Dependencies{
		Lifecycle:     store,
		Configuration: testConfiguration{},
		Clock:         func() time.Time { return testNow() },
		Logger:        testLogger{},
		Auth:          AuthConfig{Mode: AuthModeToken, APIToken: "admin-token"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := tokenRequest(t, adminServer, http.MethodGet, "/", ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated browser status = %d, want 401", got.Code)
	}
	wrong := tokenRequest(t, adminServer, http.MethodGet, "/api/v1/identities", "Bearer wrong")
	if wrong.Code != http.StatusUnauthorized || !strings.HasPrefix(wrong.Header().Get("Content-Type"), protocolContentType()) {
		t.Fatalf("wrong API token = (%d, %q), want protocol 401", wrong.Code, wrong.Header().Get("Content-Type"))
	}
	for _, header := range []string{"Bearer", "Basic secret", "Bearer one two"} {
		if got := tokenRequest(t, adminServer, http.MethodGet, "/api/v1/identities", header); got.Code != http.StatusUnauthorized {
			t.Errorf("malformed authorization %q status = %d, want 401", header, got.Code)
		}
	}
	if got := tokenRequest(t, adminServer, http.MethodGet, "/api/v1/configuration", "Bearer admin-token"); got.Code != http.StatusOK {
		t.Fatalf("valid token status = %d, want 200", got.Code)
	}
	if got := tokenRequest(t, adminServer, http.MethodPost, "/api/v1/identities/payments-api/rotations", "Bearer admin-token"); got.Code != http.StatusOK {
		t.Fatalf("admin rotate status = %d, want 200", got.Code)
	}

	operatorFile := writeTokenFile(t, "ci", "operator", "operator-token")
	operatorHandler, err := NewServer(Dependencies{
		Lifecycle:     testStore(t),
		Configuration: testConfiguration{},
		Clock:         func() time.Time { return testNow() },
		Logger:        testLogger{},
		Auth:          AuthConfig{Mode: AuthModeToken, APITokensFile: operatorFile},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := tokenRequest(t, operatorHandler, http.MethodPost, "/api/v1/identities/payments-api/rotations", "Bearer operator-token"); got.Code != http.StatusOK {
		t.Fatalf("operator rotate status = %d, want 200", got.Code)
	}
	if got := tokenRequest(t, operatorHandler, http.MethodDelete, "/api/v1/identities/payments-api", "Bearer operator-token"); got.Code != http.StatusForbidden {
		t.Fatalf("operator delete status = %d, want 403", got.Code)
	}
	if got := tokenRequest(t, operatorHandler, http.MethodPost, "/api/v1/demo/identities", "Bearer operator-token"); got.Code != http.StatusForbidden {
		t.Fatalf("operator provision status = %d, want 403", got.Code)
	}

	// A file-backed role change takes effect without restarting the server.
	writeTokenFileContents(t, operatorFile, `[{"name":"ci","token_sha256":"`+digestHex("operator-token")+`","role":"viewer"}]`)
	if got := tokenRequest(t, operatorHandler, http.MethodPost, "/api/v1/identities/payments-api/rotations", "Bearer operator-token"); got.Code != http.StatusForbidden {
		t.Fatalf("revoked operator role status = %d, want 403", got.Code)
	}
	writeTokenFileContents(t, operatorFile, `[]`)
	if got := tokenRequest(t, operatorHandler, http.MethodGet, "/api/v1/identities", "Bearer operator-token"); got.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token status = %d, want 401", got.Code)
	}
}

func TestBrowserSessionCSRFAndBearerBypass(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	store := NewMemorySessionStore()
	clock := func() time.Time { return testNow() }
	if _, err := newAuthenticator(AuthConfig{
		Mode:         AuthModeOIDC,
		IssuerURL:    "http://issuer.example",
		ClientID:     "client",
		ClientSecret: "secret",
		SessionKey:   key,
		SessionStore: store,
	}, clock); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), "session-1", Session{Principal: "user@example.test", Subject: "sub", Role: RoleOperator, ExpiresAt: testNow().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	signed, err := signValue("session-1", key)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewServer(Dependencies{
		Lifecycle:     testStore(t),
		Configuration: testConfiguration{},
		Clock:         clock,
		Logger:        testLogger{},
		Auth: AuthConfig{
			Mode:         AuthModeOIDC,
			IssuerURL:    "http://issuer.example",
			ClientID:     "client",
			ClientSecret: "secret",
			SessionKey:   key,
			SessionStore: store,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	withoutCSRF := httptest.NewRequest(http.MethodPost, "/api/v1/identities/payments-api/rotations", nil)
	withoutCSRF.AddCookie(&http.Cookie{Name: sessionCookieName, Value: signed})
	blocked := httptest.NewRecorder()
	handler.ServeHTTP(blocked, withoutCSRF)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("browser mutation without CSRF = %d, want 403", blocked.Code)
	}
	withCSRF := httptest.NewRequest(http.MethodPost, "/api/v1/identities/payments-api/rotations", nil)
	withCSRF.AddCookie(&http.Cookie{Name: sessionCookieName, Value: signed})
	withCSRF.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-value"})
	withCSRF.Header.Set("X-Mutandae-CSRF", "csrf-value")
	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, withCSRF)
	if allowed.Code != http.StatusOK {
		t.Fatalf("browser mutation with CSRF = %d, want 200", allowed.Code)
	}
	bearer := tokenRequest(t, mustServer(t, Dependencies{
		Lifecycle: testStore(t), Configuration: testConfiguration{}, Clock: clock, Logger: testLogger{},
		Auth: AuthConfig{Mode: AuthModeToken, APIToken: "operator-token"},
	}), http.MethodPost, "/api/v1/identities/payments-api/rotations", "Bearer operator-token")
	if bearer.Code != http.StatusOK {
		t.Fatalf("bearer mutation without CSRF = %d, want 200", bearer.Code)
	}
}

func TestOIDCBrowserFlowAndValidation(t *testing.T) {
	issuer := newFakeOIDC(t)
	defer issuer.Close()
	clock := func() time.Time { return testNow() }
	key := []byte("0123456789abcdef0123456789abcdef")
	handler, err := NewServer(Dependencies{
		Lifecycle:     testStore(t),
		Configuration: testConfiguration{},
		Clock:         clock,
		Logger:        testLogger{},
		Auth: AuthConfig{
			Mode: AuthModeOIDC, IssuerURL: issuer.URL, ClientID: "client-id", ClientSecret: "client-secret",
			SessionKey: key, HTTPClient: issuer.Client(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	login, stateCookie, query := oidcLogin(t, handler)
	if login.Code != http.StatusFound || query.Get("code_challenge_method") != "S256" || query.Get("nonce") == "" {
		t.Fatalf("login response = %d, location = %q", login.Code, login.Header().Get("Location"))
	}
	issuer.setCode("good", oidcTokenSpec{Nonce: query.Get("nonce"), Audience: "client-id", Kid: "key-1", ExpiresAt: testNow().Add(time.Minute)})
	callback := oidcCallback(t, handler, stateCookie, query.Get("state"), "good")
	if callback.Code != http.StatusFound || len(callback.Result().Cookies()) == 0 {
		t.Fatalf("callback response = %d, cookies = %#v", callback.Code, callback.Result().Cookies())
	}
	sessionCookie := cookieNamed(callback.Result().Cookies(), sessionCookieName)
	if sessionCookie == nil {
		t.Fatal("callback did not set a session cookie")
	}
	dashboard := httptest.NewRequest(http.MethodGet, "/", nil)
	dashboard.AddCookie(sessionCookie)
	dashboardResult := httptest.NewRecorder()
	handler.ServeHTTP(dashboardResult, dashboard)
	if dashboardResult.Code != http.StatusOK || !strings.Contains(dashboardResult.Body.String(), "user@example.test") || !strings.Contains(dashboardResult.Body.String(), "viewer") {
		t.Fatalf("authenticated dashboard = %d, body lacks principal/role", dashboardResult.Code)
	}

	// Invalid state is rejected before token exchange.
	_, invalidCookie, invalidQuery := oidcLogin(t, handler)
	badState := oidcCallback(t, handler, invalidCookie, invalidQuery.Get("state")+"x", "good")
	if badState.Code != http.StatusBadRequest {
		t.Fatalf("invalid state status = %d, want 400", badState.Code)
	}

	cases := []struct {
		name   string
		code   string
		mutate func(*oidcTokenSpec)
	}{
		{name: "expired", code: "expired", mutate: func(spec *oidcTokenSpec) { spec.ExpiresAt = testNow().Add(-time.Second) }},
		{name: "wrong audience", code: "wrong-audience", mutate: func(spec *oidcTokenSpec) { spec.Audience = "other-client" }},
		{name: "nonce mismatch", code: "wrong-nonce", mutate: func(spec *oidcTokenSpec) { spec.Nonce = "not-the-login-nonce" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, cookie, values := oidcLogin(t, handler)
			spec := oidcTokenSpec{Nonce: values.Get("nonce"), Audience: "client-id", Kid: "key-1", ExpiresAt: testNow().Add(time.Minute)}
			test.mutate(&spec)
			issuer.setCode(test.code, spec)
			result := oidcCallback(t, handler, cookie, values.Get("state"), test.code)
			if result.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", result.Code)
			}
		})
	}

	// The first successful callback populated the cached key set. Switching to
	// a new signing key exercises the unknown-kid forced JWKS refresh path.
	newKey := generateRSAKey(t)
	issuer.setCurrentKey("key-2", newKey)
	_, refreshCookie, refreshQuery := oidcLogin(t, handler)
	issuer.setCode("refresh", oidcTokenSpec{Nonce: refreshQuery.Get("nonce"), Audience: "client-id", Kid: "key-2", ExpiresAt: testNow().Add(time.Minute)})
	refresh := oidcCallback(t, handler, refreshCookie, refreshQuery.Get("state"), "refresh")
	if refresh.Code != http.StatusFound || issuer.jwksRequests() < 2 {
		t.Fatalf("JWKS refresh callback = %d, requests = %d", refresh.Code, issuer.jwksRequests())
	}
}

func oidcLogin(t *testing.T, handler http.Handler) (*httptest.ResponseRecorder, *http.Cookie, url.Values) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://app.example/auth/login?return_to=%2F", nil)
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, req)
	location, err := url.Parse(result.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse login location: %v", err)
	}
	cookie := cookieNamed(result.Result().Cookies(), oidcStateCookie)
	if cookie == nil {
		t.Fatal("login did not set state cookie")
	}
	return result, cookie, location.Query()
}

func oidcCallback(t *testing.T, handler http.Handler, stateCookie *http.Cookie, state, code string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://app.example/auth/callback?state="+url.QueryEscape(state)+"&code="+url.QueryEscape(code), nil)
	req.AddCookie(stateCookie)
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, req)
	return result
}

func writeTokenFile(t *testing.T, name, role, token string) string {
	t.Helper()
	file := t.TempDir() + "/tokens.json"
	writeTokenFileContents(t, file, `[{"name":"`+name+`","token_sha256":"`+digestHex(token)+`","role":"`+role+`"}]`)
	return file
}

func writeTokenFileContents(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func digestHex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func cookieNamed(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func mustServer(t *testing.T, deps Dependencies) http.Handler {
	t.Helper()
	handler, err := NewServer(deps)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

// protocolContentType avoids importing protocol only to compare its constant
// in the small token response assertion above; the protocol media type is part
// of the public HTTP contract.
func protocolContentType() string { return "application/vnd.mutandae.v1+json" }

type oidcTokenSpec struct {
	Nonce     string
	Audience  string
	Kid       string
	ExpiresAt time.Time
}

type fakeOIDC struct {
	*httptest.Server
	mu         sync.Mutex
	keys       map[string]*rsa.PrivateKey
	currentKid string
	currentKey *rsa.PrivateKey
	codes      map[string]oidcTokenSpec
	jwksCount  int
}

func newFakeOIDC(t *testing.T) *fakeOIDC {
	t.Helper()
	key := generateRSAKey(t)
	fake := &fakeOIDC{keys: map[string]*rsa.PrivateKey{"key-1": key}, currentKid: "key-1", currentKey: key, codes: make(map[string]oidcTokenSpec)}
	fake.Server = httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
	return fake
}

func (f *fakeOIDC) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		base := "http://" + r.Host
		writeJSONForTest(w, map[string]string{
			"issuer": base, "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token", "jwks_uri": base + "/jwks",
		})
	case "/token":
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		spec, ok := f.codes[r.Form.Get("code")]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		token, err := f.signToken(spec)
		if err != nil {
			http.Error(w, "unable to sign test token", http.StatusInternalServerError)
			return
		}
		writeJSONForTest(w, map[string]string{"id_token": token, "token_type": "Bearer"})
	case "/jwks":
		f.mu.Lock()
		f.jwksCount++
		keys := make(map[string]*rsa.PrivateKey, len(f.keys))
		for kid, key := range f.keys {
			keys[kid] = key
		}
		f.mu.Unlock()
		out := make([]map[string]string, 0, len(keys))
		for kid, key := range keys {
			out = append(out, rsaJWK(kid, &key.PublicKey))
		}
		writeJSONForTest(w, map[string]any{"keys": out})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeOIDC) signToken(spec oidcTokenSpec) (string, error) {
	f.mu.Lock()
	key := f.currentKey
	currentKid := f.currentKid
	f.mu.Unlock()
	kid := spec.Kid
	if kid == "" {
		kid = currentKid
	}
	payload := map[string]any{
		"iss": f.URL, "aud": spec.Audience, "exp": spec.ExpiresAt.Unix(), "nonce": spec.Nonce,
		"sub": "subject-1", "email": "user@example.test", "name": "OIDC User", "role": "viewer",
	}
	return signJWT(key, kid, payload)
}

func (f *fakeOIDC) setCode(code string, spec oidcTokenSpec) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.codes[code] = spec
}

func (f *fakeOIDC) setCurrentKey(kid string, key *rsa.PrivateKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.currentKid, f.currentKey = kid, key
	f.keys[kid] = key
}

func (f *fakeOIDC) jwksRequests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.jwksCount
}

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signJWT(key *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	encode := func(value any) (string, error) {
		raw, err := json.Marshal(value)
		if err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(raw), nil
	}
	header, err := encode(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := encode(claims)
	if err != nil {
		return "", err
	}
	input := header + "." + payload
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func rsaJWK(kid string, key *rsa.PublicKey) map[string]string {
	// The fake uses the conventional RSA exponent 65537, encoded as the
	// minimal unsigned big-endian JWK integer.
	return map[string]string{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
	}
}

func writeJSONForTest(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
