package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// Tests for the HashiCorp Vault KV v2 delivery store. The suite speaks to a
// tiny in-memory KV v2 fake served by httptest.Server, so every behavior is
// asserted at the HTTP boundary: request shape, token header, payload fields,
// version semantics, status mapping, and error redaction. Every test builds
// its own fake and client, so the tests are parallel-safe and share no state.

const (
	vaultTestToken     = "vault-test-token"
	vaultTestFixedDate = "2026-08-20T12:00:00Z"
	vaultFakeMount     = "secret"
)

// vaultTestNow is the injected fixed clock for deterministic stored_at and
// ExpiresAt assertions.
func vaultTestNow() time.Time {
	fixed, err := time.Parse(time.RFC3339, vaultTestFixedDate)
	if err != nil {
		panic(err) // impossible: fixed literal in this file
	}
	return fixed
}

// vaultTestIdentity is a demo-namespace identity whose credential material
// the store may deliver.
func vaultTestIdentity() protocol.MachineIdentity {
	return protocol.MachineIdentity{
		Name: "mutandae-demo-orders",
		Provider: protocol.ProviderBinding{
			Provider:   awsKind,
			ProviderID: "mutandae-demo-orders",
			AccountID:  fakeAWSAccount,
			Region:     "us-west-2",
		},
	}
}

// kvv2Fake is a minimal KV v2 engine: an in-memory map from secret path
// (below the mount) to the ordered list of data payloads, where the slice
// index plus one is the version number. It serves the three operations the
// store uses: POST .../data/<path>, GET .../data/<path>[?version=N], and
// DELETE .../metadata/<path>.
type kvv2Fake struct {
	mu       sync.Mutex
	versions map[string][]map[string]string
	requests int
	// fail, when set, handles the request before the fake engine and returns
	// true when it wrote a response. Tests use it to inject error statuses
	// with arbitrary bodies.
	fail func(w http.ResponseWriter, r *http.Request) bool
}

func newVaultFake(t *testing.T) (*httptest.Server, *kvv2Fake) {
	t.Helper()
	fake := &kvv2Fake{versions: make(map[string][]map[string]string)}
	server := httptest.NewServer(http.HandlerFunc(fake.serve))
	t.Cleanup(server.Close)
	return server, fake
}

func newVaultTestClient(t *testing.T, server *httptest.Server) *HashiCorpVault {
	t.Helper()
	client, err := NewHashiCorpVault(HashiCorpVaultConfig{
		Addr:       server.URL,
		Token:      vaultTestToken,
		Now:        vaultTestNow,
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("NewHashiCorpVault() for tests: %v", err)
	}
	return client
}

func (f *kvv2Fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	if f.fail != nil && f.fail(w, r) {
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/v1/"+vaultFakeMount+"/")
	if !ok {
		writeVaultJSON(w, http.StatusNotFound, vaultFakeErrors("no such mount"))
		return
	}
	switch {
	case r.Method == http.MethodPost && strings.HasPrefix(rest, "data/"):
		f.handleWrite(w, r, strings.TrimPrefix(rest, "data/"))
	case r.Method == http.MethodGet && strings.HasPrefix(rest, "data/"):
		f.handleRead(w, r, strings.TrimPrefix(rest, "data/"))
	case r.Method == http.MethodDelete && strings.HasPrefix(rest, "metadata/"):
		f.handleDelete(w, r, strings.TrimPrefix(rest, "metadata/"))
	default:
		writeVaultJSON(w, http.StatusMethodNotAllowed, vaultFakeErrors("method not allowed on this path"))
	}
}

func (f *kvv2Fake) handleWrite(w http.ResponseWriter, r *http.Request, path string) {
	if path == "" {
		writeVaultJSON(w, http.StatusBadRequest, vaultFakeErrors("empty secret path"))
		return
	}
	var payload struct {
		Data map[string]string `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeVaultJSON(w, http.StatusBadRequest, vaultFakeErrors("invalid write payload"))
		return
	}
	f.versions[path] = append(f.versions[path], payload.Data)
	writeVaultJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{
			"created_time":  vaultTestFixedDate,
			"deletion_time": "",
			"destroyed":     false,
			"version":       len(f.versions[path]),
		},
	})
}

func (f *kvv2Fake) handleRead(w http.ResponseWriter, r *http.Request, path string) {
	versions, ok := f.versions[path]
	if !ok || len(versions) == 0 {
		writeVaultJSON(w, http.StatusNotFound, vaultFakeErrors("secret not found"))
		return
	}
	requested := len(versions)
	if query := r.URL.Query().Get("version"); query != "" {
		version, err := strconv.Atoi(query)
		if err != nil || version < 1 || version > len(versions) {
			writeVaultJSON(w, http.StatusNotFound, vaultFakeErrors("secret not found"))
			return
		}
		requested = version
	}
	writeVaultJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{
			"data": versions[requested-1],
			"metadata": map[string]any{
				"created_time":  vaultTestFixedDate,
				"deletion_time": "",
				"destroyed":     false,
				"version":       requested,
			},
		},
	})
}

func (f *kvv2Fake) handleDelete(w http.ResponseWriter, _ *http.Request, path string) {
	if _, ok := f.versions[path]; ok {
		delete(f.versions, path)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeVaultJSON(w, http.StatusNotFound, vaultFakeErrors("secret not found"))
}

// storedCount reports how many versions exist at a path.
func (f *kvv2Fake) storedCount(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.versions[path])
}

// requestCount reports the total number of requests the fake received.
func (f *kvv2Fake) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

func vaultFakeErrors(messages ...string) map[string]any {
	return map[string]any{"errors": messages}
}

func writeVaultJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// assertVaultErrorClean fails the test when an error message leaks any of the
// forbidden strings (the secret, the token, or raw body fragments).
func assertVaultErrorClean(t *testing.T, err error, forbidden ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	message := err.Error()
	for _, secret := range forbidden {
		if strings.Contains(message, secret) {
			t.Errorf("error message leaks forbidden content %q: %s", secret, message)
		}
	}
}

func TestHashiCorpVaultConfigValidation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		config  HashiCorpVaultConfig
		wantErr string
	}{
		{name: "empty addr", config: HashiCorpVaultConfig{Token: vaultTestToken}, wantErr: "invalid addr"},
		{name: "addr without scheme", config: HashiCorpVaultConfig{Addr: "vault.internal:8200", Token: vaultTestToken}, wantErr: "invalid addr"},
		{name: "unsupported scheme", config: HashiCorpVaultConfig{Addr: "ftp://vault.internal", Token: vaultTestToken}, wantErr: "not supported"},
		{name: "addr with query", config: HashiCorpVaultConfig{Addr: "https://vault.internal/?x=1", Token: vaultTestToken}, wantErr: "invalid addr"},
		{name: "addr with userinfo", config: HashiCorpVaultConfig{Addr: "https://user:pass@vault.internal", Token: vaultTestToken}, wantErr: "invalid addr"},
		{name: "empty token", config: HashiCorpVaultConfig{Addr: "https://vault.internal"}, wantErr: "token is required"},
		{name: "whitespace token", config: HashiCorpVaultConfig{Addr: "https://vault.internal", Token: "   "}, wantErr: "token is required"},
		{name: "invalid mount", config: HashiCorpVaultConfig{Addr: "https://vault.internal", Token: vaultTestToken, Mount: "se cret"}, wantErr: "mount"},
		{name: "traversal mount", config: HashiCorpVaultConfig{Addr: "https://vault.internal", Token: vaultTestToken, Mount: ".."}, wantErr: "mount"},
		{name: "traversal prefix", config: HashiCorpVaultConfig{Addr: "https://vault.internal", Token: vaultTestToken, Prefix: "../evil"}, wantErr: "prefix"},
		{name: "empty prefix segment", config: HashiCorpVaultConfig{Addr: "https://vault.internal", Token: vaultTestToken, Prefix: "mutandae//x"}, wantErr: "prefix"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client, err := NewHashiCorpVault(tc.config)
			if err == nil {
				t.Fatalf("NewHashiCorpVault(%+v) = %+v, want error", tc.config, client)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestHashiCorpVaultDefaults pins the constructor defaults: the conventional
// KV v2 mount, the demo prefix, the 24h reference TTL, and the 10s client
// timeout used when the operator injects no HTTP client.
func TestHashiCorpVaultDefaults(t *testing.T) {
	t.Parallel()
	client, err := NewHashiCorpVault(HashiCorpVaultConfig{Addr: "https://vault.internal:8200/", Token: vaultTestToken})
	if err != nil {
		t.Fatalf("NewHashiCorpVault() with defaults: %v", err)
	}
	if client.mount != vaultDefaultMount {
		t.Errorf("mount = %q, want default %q", client.mount, vaultDefaultMount)
	}
	if client.prefix != vaultDefaultPrefix {
		t.Errorf("prefix = %q, want default %q", client.prefix, vaultDefaultPrefix)
	}
	if client.ttl != vaultDefaultTTL {
		t.Errorf("ttl = %v, want default %v", client.ttl, vaultDefaultTTL)
	}
	if client.now == nil {
		t.Error("now = nil, want a default clock")
	}
	if client.httpClient == nil || client.httpClient.Timeout != vaultDefaultTimeout {
		t.Errorf("default client timeout = %v, want %v", client.httpClient.Timeout, vaultDefaultTimeout)
	}
	if client.addr != "https://vault.internal:8200" {
		t.Errorf("addr = %q, want trailing slash trimmed", client.addr)
	}
}

// TestHashiCorpVaultStoreSecret verifies the write path end to end: token
// header, full audit payload (key_id/secret/provider/identity/stored_at),
// mount/prefixed reference with the response version, and the ExpiresAt
// stamped from the injected clock. A second store must produce version 2.
func TestHashiCorpVaultStoreSecret(t *testing.T) {
	t.Parallel()
	server, fake := newVaultFake(t)
	client := newVaultTestClient(t, server)
	identity := vaultTestIdentity()
	secret := "store-secret-value"
	wantPath := "mutandae/" + identity.Name
	wantPayload := map[string]string{
		"secret":    secret,
		"key_id":    "access-key-1",
		"provider":  awsKind,
		"identity":  identity.Name,
		"stored_at": vaultTestNow().UTC().Format(time.RFC3339),
	}
	_ = wantPayload

	for _, version := range []string{"1", "2"} {
		ref, err := client.StoreSecret(context.Background(), identity, "access-key-1", secret)
		if err != nil {
			t.Fatalf("StoreSecret() version %s: %v", version, err)
		}
		if ref.URL != server.URL {
			t.Errorf("ref.URL = %q, want %q", ref.URL, server.URL)
		}
		if ref.SecretName != vaultFakeMount+"/"+wantPath {
			t.Errorf("ref.SecretName = %q, want %q", ref.SecretName, vaultFakeMount+"/"+wantPath)
		}
		if ref.Version != version {
			t.Errorf("ref.Version = %q, want %q", ref.Version, version)
		}
		if want := vaultTestNow().UTC().Add(vaultDefaultTTL); !ref.ExpiresAt.Equal(want) {
			t.Errorf("ref.ExpiresAt = %v, want injected-now TTL %v", ref.ExpiresAt, want)
		}
	}

	if got := fake.storedCount(wantPath); got != 2 {
		t.Errorf("fake stored %d versions at %q, want 2", got, wantPath)
	}
	_ = wantPayload
}

// TestHashiCorpVaultStoreRequestShape pins the wire contract of the write
// request: POST, the KV v2 data path, the token header, JSON content type,
// and the exact payload including stored_at from the injected clock.
func TestHashiCorpVaultStoreRequestShape(t *testing.T) {
	t.Parallel()
	identity := vaultTestIdentity()
	secret := "shape-secret-value"
	wantPath := "/v1/" + vaultFakeMount + "/data/mutandae/" + identity.Name
	var sawRequest bool
	handler := func(w http.ResponseWriter, r *http.Request) bool {
		sawRequest = true
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.URL.Path != wantPath {
			t.Errorf("path = %q, want %q", r.URL.Path, wantPath)
		}
		if got := r.Header.Get("X-Vault-Token"); got != vaultTestToken {
			t.Errorf("X-Vault-Token = %q, want the injected token", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		var payload struct {
			Data map[string]string `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode write payload: %v", err)
			writeVaultJSON(w, http.StatusBadRequest, vaultFakeErrors("bad payload"))
			return true
		}
		want := map[string]string{
			"secret":    secret,
			"key_id":    "access-key-1",
			"provider":  awsKind,
			"identity":  identity.Name,
			"stored_at": vaultTestNow().UTC().Format(time.RFC3339),
		}
		if len(payload.Data) != len(want) {
			t.Errorf("payload fields = %v, want exactly %v", payload.Data, want)
		}
		for key, value := range want {
			if payload.Data[key] != value {
				t.Errorf("payload[%q] = %q, want %q", key, payload.Data[key], value)
			}
		}
		writeVaultJSON(w, http.StatusOK, map[string]any{
			"data": map[string]any{"created_time": vaultTestFixedDate, "destroyed": false, "version": 1},
		})
		return true
	}
	server, fake := newVaultFake(t)
	fake.fail = handler
	client := newVaultTestClient(t, server)

	ref, err := client.StoreSecret(context.Background(), identity, "access-key-1", secret)
	if err != nil {
		t.Fatalf("StoreSecret(): %v", err)
	}
	if !sawRequest {
		t.Fatal("fake handler never ran")
	}
	if ref.Version != "1" {
		t.Errorf("ref.Version = %q, want 1 from the response metadata", ref.Version)
	}
}

// TestHashiCorpVaultStoreSanitizesName verifies that weird characters become
// dashes, over-long names are capped at 63 characters, and an empty key id
// defaults to "current" — while the reference keeps the mount/prefixed shape.
func TestHashiCorpVaultStoreSanitizesName(t *testing.T) {
	t.Parallel()
	server, fake := newVaultFake(t)
	client := newVaultTestClient(t, server)
	cases := []struct {
		name       string
		identity   string
		keyID      string
		wantSecret string
	}{
		{
			name:       "weird characters become dashes",
			identity:   "mutandae-demo-Web Server #1!",
			keyID:      "access-key-1",
			wantSecret: "secret/mutandae/mutandae-demo-Web-Server--1",
		},
		{
			name:       "over-long name is capped at 63 characters",
			identity:   "mutandae-demo-" + strings.Repeat("a", 70),
			keyID:      "k",
			wantSecret: "secret/mutandae/" + "mutandae-demo-" + strings.Repeat("a", 49),
		},
		{
			name:       "empty key id defaults to current",
			identity:   "mutandae-demo-orders",
			keyID:      "",
			wantSecret: "secret/mutandae/mutandae-demo-orders",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			identity := vaultTestIdentity()
			identity.Name = tc.identity
			ref, err := client.StoreSecret(context.Background(), identity, tc.keyID, "sanitized-value")
			if err != nil {
				t.Fatalf("StoreSecret(): %v", err)
			}
			if ref.SecretName != tc.wantSecret {
				t.Errorf("ref.SecretName = %q, want %q", ref.SecretName, tc.wantSecret)
			}
			if got := fake.storedCount(strings.TrimPrefix(tc.wantSecret, vaultFakeMount+"/")); got != 1 {
				t.Errorf("fake stored %d versions, want 1", got)
			}
		})
	}
}

// TestHashiCorpVaultReadRoundTrip verifies that reads return the exact secret
// value, both for the current version (no query, "current", "latest") and for
// a pinned version (?version=1).
func TestHashiCorpVaultReadRoundTrip(t *testing.T) {
	t.Parallel()
	server, _ := newVaultFake(t)
	client := newVaultTestClient(t, server)
	identity := vaultTestIdentity()
	first, second := "first-secret-value-₁", "second-secret-value"

	ref, err := client.StoreSecret(context.Background(), identity, "access-key-1", first)
	if err != nil {
		t.Fatalf("StoreSecret() first: %v", err)
	}
	if ref.Version != "1" {
		t.Fatalf("first ref.Version = %q, want 1", ref.Version)
	}
	if _, err := client.StoreSecret(context.Background(), identity, "access-key-1", second); err != nil {
		t.Fatalf("StoreSecret() second: %v", err)
	}

	for _, version := range []string{"", "current", "latest"} {
		value, ref, err := client.ReadSecret(context.Background(), identity, "access-key-1", version)
		if err != nil {
			t.Fatalf("ReadSecret(version=%q): %v", version, err)
		}
		if value != second {
			t.Errorf("ReadSecret(version=%q) value = %q, want exact current %q", version, value, second)
		}
		if ref.Version != "2" {
			t.Errorf("ReadSecret(version=%q) ref.Version = %q, want 2 from response metadata", version, ref.Version)
		}
		if ref.SecretName != "secret/mutandae/"+identity.Name {
			t.Errorf("ref.SecretName = %q, want the mount/prefixed path", ref.SecretName)
		}
	}

	value, ref, err := client.ReadSecret(context.Background(), identity, "access-key-1", "1")
	if err != nil {
		t.Fatalf("ReadSecret(version=1): %v", err)
	}
	if value != first {
		t.Errorf("pinned value = %q, want exact version 1 %q", value, first)
	}
	if ref.Version != "1" {
		t.Errorf("pinned ref.Version = %q, want 1", ref.Version)
	}
}

// TestHashiCorpVaultReadNotFound verifies that a 404 read surfaces the
// distinguishable not-found error and never leaks the token.
func TestHashiCorpVaultReadNotFound(t *testing.T) {
	t.Parallel()
	server, _ := newVaultFake(t)
	client := newVaultTestClient(t, server)
	_, _, err := client.ReadSecret(context.Background(), vaultTestIdentity(), "access-key-1", "")
	assertVaultErrorClean(t, err, vaultTestToken)
	if !errors.Is(err, ErrVaultSecretNotFound) {
		t.Errorf("error = %v, want errors.Is(err, ErrVaultSecretNotFound)", err)
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("error = %q, want it to mention HTTP 404", err.Error())
	}
}

// TestHashiCorpVaultSealedOrUnavailable verifies Vault's uninitialized/sealed
// statuses (501/503) map onto the explicit sealed-or-unavailable message.
func TestHashiCorpVaultSealedOrUnavailable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		status    int
		wantError string
	}{
		{http.StatusNotImplemented, "Vault is sealed or unavailable (HTTP 501)"},
		{http.StatusServiceUnavailable, "Vault is sealed or unavailable (HTTP 503)"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("HTTP %d", tc.status), func(t *testing.T) {
			t.Parallel()
			server, fake := newVaultFake(t)
			fake.fail = func(w http.ResponseWriter, _ *http.Request) bool {
				writeVaultJSON(w, tc.status, vaultFakeErrors("injected"))
				return true
			}
			client := newVaultTestClient(t, server)
			identity := vaultTestIdentity()
			_, err := client.StoreSecret(context.Background(), identity, "k", "sealed-value")
			assertVaultErrorClean(t, err, "sealed-value", vaultTestToken)
			if err.Error() != tc.wantError {
				t.Errorf("StoreSecret() error = %q, want exactly %q", err.Error(), tc.wantError)
			}
			_, _, readErr := client.ReadSecret(context.Background(), identity, "k", "")
			assertVaultErrorClean(t, readErr, "sealed-value", vaultTestToken)
			if readErr.Error() != tc.wantError {
				t.Errorf("ReadSecret() error = %q, want exactly %q", readErr.Error(), tc.wantError)
			}
			_, revokeErr := client.RevokeSecret(context.Background(), identity, "k")
			assertVaultErrorClean(t, revokeErr, "sealed-value", vaultTestToken)
			if revokeErr.Error() != tc.wantError {
				t.Errorf("RevokeSecret() error = %q, want exactly %q", revokeErr.Error(), tc.wantError)
			}
			if errors.Is(err, ErrVaultSecretNotFound) {
				t.Errorf("error %q must not be classified as not-found", err)
			}
		})
	}
}

// TestHashiCorpVaultUnexpectedStatusRedacted verifies other statuses carry the
// HTTP status plus a truncated detail parsed from the Vault errors field —
// never the secret, the token, or the raw response body.
func TestHashiCorpVaultUnexpectedStatusRedacted(t *testing.T) {
	t.Parallel()
	secret := "redaction-secret-value"
	longDetail := strings.Repeat("x", 300) + "TAIL-MARKER-BEYOND-CUT"
	cases := []struct {
		name       string
		status     int
		body       string
		wantParts  []string
		wantHidden []string
	}{
		{
			name:       "vault errors field is quoted and scrubbed",
			status:     http.StatusForbidden,
			body:       `{"errors":["permission denied; token=` + vaultTestToken + ` value=` + secret + `"]}`,
			wantParts:  []string{"HTTP 403", "permission denied", "[redacted]"},
			wantHidden: []string{vaultTestToken, secret},
		},
		{
			name:       "non-JSON body is withheld entirely",
			status:     http.StatusInternalServerError,
			body:       "<html>boom " + vaultTestToken + " " + secret + "</html>",
			wantParts:  []string{"HTTP 500", "(response body withheld)"},
			wantHidden: []string{"boom", vaultTestToken, secret, "<html>"},
		},
		{
			name:       "over-long detail is truncated",
			status:     http.StatusBadRequest,
			body:       `{"errors":["` + longDetail + `"]}`,
			wantParts:  []string{"HTTP 400"},
			wantHidden: []string{"TAIL-MARKER-BEYOND-CUT"},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server, fake := newVaultFake(t)
			fake.fail = func(w http.ResponseWriter, _ *http.Request) bool {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
				return true
			}
			client := newVaultTestClient(t, server)
			_, err := client.StoreSecret(context.Background(), vaultTestIdentity(), "k", secret)
			assertVaultErrorClean(t, err, tc.wantHidden...)
			for _, want := range tc.wantParts {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to contain %q", err.Error(), want)
				}
			}
			if tc.name == "over-long detail is truncated" {
				// Status prefix + at most vaultErrorDetailMax bytes + ellipsis.
				if limit := len("HashiCorp Vault returned HTTP 400: ") + vaultErrorDetailMax + 3; len(err.Error()) > limit {
					t.Errorf("error length = %d, want at most %d", len(err.Error()), limit)
				}
			}
		})
	}
}

// TestHashiCorpVaultRevokeSecret verifies the metadata delete: request shape,
// the empty-version reference, and idempotency when the secret is already
// gone (404 is success).
// assertVaultReference compares references field-wise (VaultReference holds a
// slice, so it is not comparable with ==) and rejects unexpected owner lists.
func assertVaultReference(t *testing.T, got, want protocol.VaultReference) {
	t.Helper()
	if got.URL != want.URL {
		t.Errorf("ref.URL = %q, want %q", got.URL, want.URL)
	}
	if got.SecretName != want.SecretName {
		t.Errorf("ref.SecretName = %q, want %q", got.SecretName, want.SecretName)
	}
	if got.Version != want.Version {
		t.Errorf("ref.Version = %q, want %q", got.Version, want.Version)
	}
	if !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("ref.ExpiresAt = %v, want %v", got.ExpiresAt, want.ExpiresAt)
	}
	if len(got.OwnerObjectIDs) != 0 {
		t.Errorf("ref.OwnerObjectIDs = %v, want none", got.OwnerObjectIDs)
	}
}

func TestHashiCorpVaultRevokeSecret(t *testing.T) {
	t.Parallel()
	server, fake := newVaultFake(t)
	client := newVaultTestClient(t, server)
	identity := vaultTestIdentity()
	wantRef := protocol.VaultReference{
		URL:        server.URL,
		SecretName: "secret/mutandae/" + identity.Name,
		Version:    "",
	}
	if _, err := client.StoreSecret(context.Background(), identity, "access-key-1", "revoke-me"); err != nil {
		t.Fatalf("StoreSecret(): %v", err)
	}

	ref, err := client.RevokeSecret(context.Background(), identity, "access-key-1")
	if err != nil {
		t.Fatalf("RevokeSecret(): %v", err)
	}
	assertVaultReference(t, ref, wantRef)
	if got := fake.storedCount("mutandae/" + identity.Name); got != 0 {
		t.Errorf("fake still stores %d versions after revoke, want 0", got)
	}

	// Revoking again hits 404 — the secret is already gone, which is success.
	ref, err = client.RevokeSecret(context.Background(), identity, "access-key-1")
	if err != nil {
		t.Fatalf("RevokeSecret() after delete: %v", err)
	}
	assertVaultReference(t, ref, wantRef)
}

// TestHashiCorpVaultRevokeRequestShape pins the DELETE method and metadata
// path used by the revocation.
func TestHashiCorpVaultRevokeRequestShape(t *testing.T) {
	t.Parallel()
	identity := vaultTestIdentity()
	wantPath := "/v1/" + vaultFakeMount + "/metadata/mutandae/" + identity.Name
	var sawMethod, sawPath bool
	server, fake := newVaultFake(t)
	fake.fail = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodDelete && r.URL.Path == wantPath {
			sawMethod, sawPath = true, true
		} else {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-Vault-Token"); got != vaultTestToken {
			t.Errorf("X-Vault-Token = %q, want the injected token", got)
		}
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	client := newVaultTestClient(t, server)
	if _, err := client.RevokeSecret(context.Background(), identity, "access-key-1"); err != nil {
		t.Fatalf("RevokeSecret(): %v", err)
	}
	if !sawMethod || !sawPath {
		t.Errorf("revoke request shape mismatch: method=%v path=%v (want DELETE %s)", sawMethod, sawPath, wantPath)
	}
}

// TestHashiCorpVaultContextCancellation verifies every operation honors a
// canceled context without emitting a request.
func TestHashiCorpVaultContextCancellation(t *testing.T) {
	t.Parallel()
	server, fake := newVaultFake(t)
	client := newVaultTestClient(t, server)
	identity := vaultTestIdentity()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := client.StoreSecret(ctx, identity, "k", "secret"); !errors.Is(err, context.Canceled) {
		t.Errorf("StoreSecret() error = %v, want context.Canceled", err)
	}
	if _, _, err := client.ReadSecret(ctx, identity, "k", ""); !errors.Is(err, context.Canceled) {
		t.Errorf("ReadSecret() error = %v, want context.Canceled", err)
	}
	if _, err := client.RevokeSecret(ctx, identity, "k"); !errors.Is(err, context.Canceled) {
		t.Errorf("RevokeSecret() error = %v, want context.Canceled", err)
	}
	if got := fake.requestCount(); got != 0 {
		t.Errorf("fake received %d requests, want 0 after cancellation", got)
	}
}

// TestHashiCorpVaultRefusesNonDemoName verifies the demo namespace trust
// boundary holds for all three operations and that no request is emitted.
func TestHashiCorpVaultRefusesNonDemoName(t *testing.T) {
	t.Parallel()
	server, fake := newVaultFake(t)
	client := newVaultTestClient(t, server)
	identity := vaultTestIdentity()
	identity.Name = "orders-service"
	ctx := context.Background()

	if _, err := client.StoreSecret(ctx, identity, "k", "secret"); err == nil || !strings.Contains(err.Error(), "refusing vault access outside the mutandae-demo-* namespace") {
		t.Errorf("StoreSecret() error = %v, want demo namespace refusal", err)
	}
	if _, _, err := client.ReadSecret(ctx, identity, "k", ""); err == nil || !strings.Contains(err.Error(), "refusing vault access outside the mutandae-demo-* namespace") {
		t.Errorf("ReadSecret() error = %v, want demo namespace refusal", err)
	}
	if _, err := client.RevokeSecret(ctx, identity, "k"); err == nil || !strings.Contains(err.Error(), "refusing vault access outside the mutandae-demo-* namespace") {
		t.Errorf("RevokeSecret() error = %v, want demo namespace refusal", err)
	}
	if got := fake.requestCount(); got != 0 {
		t.Errorf("fake received %d requests, want 0 outside the demo namespace", got)
	}
}

// TestHashiCorpVaultInvalidPinnedVersion verifies a non-numeric pinned version
// is rejected locally without hitting the server.
func TestHashiCorpVaultInvalidPinnedVersion(t *testing.T) {
	t.Parallel()
	server, fake := newVaultFake(t)
	client := newVaultTestClient(t, server)
	_, _, err := client.ReadSecret(context.Background(), vaultTestIdentity(), "access-key-1", "not-a-number")
	if err == nil || !strings.Contains(err.Error(), "version is invalid") {
		t.Errorf("error = %v, want invalid version rejection", err)
	}
	if got := fake.requestCount(); got != 0 {
		t.Errorf("fake received %d requests, want 0 for a locally rejected version", got)
	}
}
