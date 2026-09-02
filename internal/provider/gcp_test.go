package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

const (
	fakeGCPProject = "mutandae-eval-project"
	fakeGCPEmail   = "ci-deployer@mutandae-eval-project.iam.gserviceaccount.com"
	fakeGCPKeyID   = "a1b2c3d4e5f6"
)

// fakeIAMServer is an in-memory Google IAM REST API server that enforces the
// key ceiling and records authenticated requests so tests can assert correct
// bearer-token usage and secret hygiene.
type fakeIAMServer struct {
	t          *testing.T
	mu         sync.Mutex
	accounts   map[string][]fakeGCPKey
	keySeq     int
	echoSecret string
	breakNext  bool
	tokens     map[string]bool // accepted bearer tokens
}

type fakeGCPKey struct {
	ID              string
	Algorithm       string
	Created         time.Time
	PrivateKeyData  string // base64 PKCS#8 PEM; returned only at create
	ValidBeforeTime string
	Index           int
}

func newFakeIAMServer(t *testing.T) *fakeIAMServer {
	return &fakeIAMServer{
		t:        t,
		accounts: map[string][]fakeGCPKey{},
		tokens:   map[string]bool{},
	}
}

func (f *fakeIAMServer) seed(email, keyID string, created time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accounts[email] = []fakeGCPKey{{
		ID:      keyID,
		Created: created,
		Index:   1,
	}}
}

func (f *fakeIAMServer) token() string {
	return "ya29.test-access-token"
}

func (f *fakeIAMServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/token") {
		var response struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
			TokenType   string `json:"token_type"`
		}
		response.AccessToken = f.token()
		response.ExpiresIn = 3600
		response.TokenType = "Bearer"
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	// Every IAM call must carry the bearer token obtained from the token URI.
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ya29.") {
		f.t.Errorf("fake IAM: missing bearer authorization on %s %s", r.Method, r.URL.Path)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.breakNext {
		f.breakNext = false
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{"code": 400, "message": "debug payload " + f.echoSecret, "status": "INVALID_ARGUMENT"},
		})
		return
	}

	switch {
	case strings.Contains(r.URL.Path, "/serviceAccounts/") && r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/keys"):
		f.listKeys(w, r)
	case strings.Contains(r.URL.Path, "/serviceAccounts/") && r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/keys"):
		f.createKey(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/projects/") && r.Method == http.MethodDelete:
		f.deleteKey(w, r)
	case strings.Contains(r.URL.Path, "/serviceAccounts?") || (strings.Contains(r.URL.Path, "/serviceAccounts") && r.Method == http.MethodGet):
		f.listServiceAccounts(w, r)
	default:
		f.t.Errorf("fake IAM: unexpected request %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

func (f *fakeIAMServer) listServiceAccounts(w http.ResponseWriter, r *http.Request) {
	var response struct {
		Accounts []gcpServiceAccount `json:"accounts"`
	}
	for email := range f.accounts {
		response.Accounts = append(response.Accounts, gcpServiceAccount{
			Name:        "projects/" + fakeGCPProject + "/serviceAccounts/" + email,
			ProjectID:   fakeGCPProject,
			UniqueID:    fakeGCPUniqueID(email),
			Email:       email,
			DisplayName: email,
		})
	}
	_ = json.NewEncoder(w).Encode(response)
}

func (f *fakeIAMServer) listKeys(w http.ResponseWriter, r *http.Request) {
	email := keyEmail(r.URL.Path)
	keys, ok := f.accounts[email]
	if !ok {
		http.Error(w, `{"error":{"code":404,"message":"not found"}}`, http.StatusNotFound)
		return
	}
	var response struct {
		Keys []gcpServiceAccountKey `json:"keys"`
	}
	for _, key := range keys {
		response.Keys = append(response.Keys, gcpServiceAccountKey{
			Name:           "projects/" + fakeGCPProject + "/serviceAccounts/" + email + "/keys/" + key.ID,
			KeyAlgorithm:   "KEY_ALG_RSA_2048_4096",
			KeyOrigin:      "GOOGLE_PROVIDED",
			KeyType:        "USER_MANAGED",
			ValidAfterTime: key.Created.UTC().Format(time.RFC3339),
			ValidBeforeTime: func() string {
				if key.ValidBeforeTime != "" {
					return key.ValidBeforeTime
				}
				return key.Created.Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339)
			}(),
		})
	}
	_ = json.NewEncoder(w).Encode(response)
}

func (f *fakeIAMServer) createKey(w http.ResponseWriter, r *http.Request) {
	email := keyEmail(r.URL.Path)
	keys, ok := f.accounts[email]
	if !ok {
		http.Error(w, `{"error":{"code":404,"message":"not found"}}`, http.StatusNotFound)
		return
	}
	if len(keys) >= gcpMaxKeys {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{"code": 400, "message": "Cannot exceed quota for service account keys", "status": "FAILED_PRECONDITION"},
		})
		return
	}
	f.keySeq++
	key := fakeGCPKey{
		ID:              fmt.Sprintf("created-key-%03d", f.keySeq),
		Algorithm:       "KEY_ALG_RSA_2048_4096",
		Created:         time.Now().UTC(),
		PrivateKeyData:  base64.StdEncoding.EncodeToString(generateKeyPEM()),
		ValidBeforeTime: time.Now().UTC().Add(90 * 24 * time.Hour).Format(time.RFC3339),
		Index:           f.keySeq,
	}
	f.accounts[email] = append(keys, key)
	_ = json.NewEncoder(w).Encode(gcpServiceAccountKey{
		Name:            "projects/" + fakeGCPProject + "/serviceAccounts/" + email + "/keys/" + key.ID,
		KeyAlgorithm:    key.Algorithm,
		KeyOrigin:       "GOOGLE_PROVIDED",
		KeyType:         "USER_MANAGED",
		ValidAfterTime:  key.Created.UTC().Format(time.RFC3339),
		ValidBeforeTime: key.ValidBeforeTime,
		PrivateKeyData:  key.PrivateKeyData,
	})
}

func (f *fakeIAMServer) deleteKey(w http.ResponseWriter, r *http.Request) {
	// DELETE /v1/projects/{project}/serviceAccounts/{email}/keys/{id}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 {
		http.NotFound(w, r)
		return
	}
	keyID := parts[len(parts)-1]
	emailUnescaped := parts[len(parts)-3] // email segment (may be url-encoded)
	email := strings.ReplaceAll(emailUnescaped, "%40", "@")
	keys, ok := f.accounts[email]
	if !ok {
		http.NotFound(w, r)
		return
	}
	kept := keys[:0]
	found := false
	for _, key := range keys {
		if key.ID == keyID {
			found = true
			continue
		}
		kept = append(kept, key)
	}
	f.accounts[email] = kept
	w.WriteHeader(http.StatusOK)
	if !found {
		// GCP returns success on deleting an already-deleted key; tolerate it.
		f.t.Logf("fake IAM: deleting nonexistent key %s tolerated", keyID)
	}
}

func keyEmail(path string) string {
	// /v1/projects/{project}/serviceAccounts/{email}/keys
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i, part := range parts {
		if part == "serviceAccounts" && i+1 < len(parts) {
			return strings.ReplaceAll(parts[i+1], "%40", "@")
		}
	}
	return ""
}

func fakeGCPUniqueID(email string) string {
	sum := sumForUniqueID(email)
	return fmt.Sprintf("%020d", sum%1_000_000_000_000_000_000)
}

func newGCPAdapterForTest(t *testing.T, server *fakeIAMServer, fixed time.Time) (*GCPAdapter, *httptest.Server) {
	t.Helper()
	httpServer := httptest.NewServer(server)
	keyJSON := gcpKeyJSONForTest(t)
	adapter, err := NewGCPAdapter(GCPAdapterConfig{
		ProjectID:  fakeGCPProject,
		Region:     "us-central1",
		KeyJSON:    keyJSON,
		TokenURI:   httpServer.URL + "/token",
		IAMBaseURL: httpServer.URL + "/v1",
		HTTPClient: httpServer.Client(),
		Now:        func() time.Time { return fixed },
	})
	if err != nil {
		t.Fatalf("NewGCPAdapter() error = %v", err)
	}
	return adapter, httpServer
}

// generateKeyPEM returns a freshly generated RSA PKCS#8 PEM. It is used for
// fake service-account key material returned by the fake IAM server.
func generateKeyPEM() []byte {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// gcpKeyJSONForTest builds a service-account JSON file whose private key is a
// stable RSA key held by this test, so the JWT assertion can be generated when
// a token is fetched.
func gcpKeyJSONForTest(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test RSA key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal test RSA key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	document := map[string]any{
		"type":         "service_account",
		"project_id":   fakeGCPProject,
		"private_key":  string(pemBytes),
		"client_email": fakeGCPEmail,
		"client_id":    fakeGCPUniqueID(fakeGCPEmail),
		"token_uri":    "https://oauth2.googleapis.com/token",
	}
	raw, _ := json.Marshal(document)
	return string(raw)
}

func sumForUniqueID(value string) uint64 {
	var sum uint64
	for _, char := range []byte(value) {
		sum = sum*31 + uint64(char)
	}
	return sum
}

func assertGCPIdentity(t *testing.T, identity protocol.MachineIdentity) {
	t.Helper()
	identity.ID = identity.Name
	if err := protocol.ValidateIdentity(&identity); err != nil {
		t.Fatalf("identity is non-conformant: %v", err)
	}
	if identity.Provider.Provider != "gcp-iam" {
		t.Errorf("provider = %q, want gcp-iam", identity.Provider.Provider)
	}
	if identity.Provider.ProjectID != fakeGCPProject {
		t.Errorf("project_id = %q, want %s", identity.Provider.ProjectID, fakeGCPProject)
	}
	if identity.Credential.Kind != "service_account_key" {
		t.Errorf("credential.kind = %q, want service_account_key", identity.Credential.Kind)
	}
	if !strings.HasPrefix(identity.Credential.Fingerprint, "sha256:") {
		t.Errorf("credential.fingerprint = %q, want sha256: prefix", identity.Credential.Fingerprint)
	}
}

func TestGCPAdapterDiscoversConformantIdentities(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	iam := newFakeIAMServer(t)
	iam.seed(fakeGCPEmail, fakeGCPKeyID, fixed.Add(-40*24*time.Hour))
	adapter, server := newGCPAdapterForTest(t, iam, fixed)
	defer server.Close()

	identities, err := adapter.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(identities) != 1 {
		t.Fatalf("Discover() returned %d identities, want 1", len(identities))
	}
	identity := identities[0]
	assertGCPIdentity(t, identity)
	if identity.Credential.KeyID != fakeGCPKeyID {
		t.Errorf("credential.key_id = %q, want %s", identity.Credential.KeyID, fakeGCPKeyID)
	}
	if strings.Contains(fmt.Sprintf("%+v", identity), fakeGCPEmail) && identity.Ownership.Service == "" {
		t.Errorf("identity did not carry an ownership label: %+v", identity.Ownership)
	}
}

func TestGCPAdapterRotateReplacesKey(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	iam := newFakeIAMServer(t)
	iam.seed(fakeGCPEmail, fakeGCPKeyID, fixed.Add(-40*24*time.Hour))
	adapter, server := newGCPAdapterForTest(t, iam, fixed)
	defer server.Close()

	discovered, err := adapter.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	identity := discovered[0]
	identity.ID = identity.Name

	rotated, err := adapter.Rotate(context.Background(), identity)
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if rotated.Credential.KeyID == identity.Credential.KeyID {
		t.Fatalf("rotate did not replace the key id")
	}
	if rotated.Credential.Fingerprint == identity.Credential.Fingerprint {
		t.Fatalf("rotate did not replace the credential fingerprint")
	}
	oneTime := adapter.ConsumeOneTimeSecret()
	if oneTime == "" {
		t.Fatal("rotation produced no one-time secret")
	}
	if adapter.ConsumeOneTimeSecret() != "" {
		t.Fatal("one-time secret was not cleared after consumption")
	}
	keys := iam.accounts[fakeGCPEmail]
	if len(keys) != 1 {
		t.Fatalf("expected exactly 1 key after rotation, got %d", len(keys))
	}
	if keys[0].ID != rotated.Credential.KeyID {
		t.Fatalf("active key %q does not match rotated evidence %q", keys[0].ID, rotated.Credential.KeyID)
	}
}

func TestGCPAdapterRetireDeletesAllKeys(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	iam := newFakeIAMServer(t)
	iam.seed(fakeGCPEmail, fakeGCPKeyID, fixed.Add(-40*24*time.Hour))
	adapter, server := newGCPAdapterForTest(t, iam, fixed)
	defer server.Close()

	identity, err := adapter.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	retired, err := adapter.Retire(context.Background(), identity[0])
	if err != nil {
		t.Fatalf("Retire() error = %v", err)
	}
	if retired.State != protocol.StateRetired {
		t.Fatalf("retired view state = %q, want retired", retired.State)
	}
	if len(iam.accounts[fakeGCPEmail]) != 0 {
		t.Fatalf("provider still holds %d keys after retire", len(iam.accounts[fakeGCPEmail]))
	}
	rediscovered, err := adapter.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() after retire error = %v", err)
	}
	if len(rediscovered) != 0 {
		t.Fatalf("retired identity was rediscovered: %+v", rediscovered)
	}
}

func TestGCPAdapterRedactsSecretsFromErrors(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	iam := newFakeIAMServer(t)
	iam.seed(fakeGCPEmail, fakeGCPKeyID, fixed.Add(-40*24*time.Hour))
	adapter, server := newGCPAdapterForTest(t, iam, fixed)
	defer server.Close()

	// Rotate first so the adapter holds a freshly created one-time secret in
	// memory; the broken call below echoes that exact value back from the
	// server so we can prove the error path redacts it.
	discovered, err := adapter.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if _, err := adapter.Rotate(context.Background(), discovered[0]); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	adapter.mu.Lock()
	secret := adapter.oneTimeSecret
	adapter.mu.Unlock()
	if secret == "" {
		t.Fatal("rotation produced no one-time secret to redact")
	}
	iam.echoSecret = secret
	iam.breakNext = true

	_, err = adapter.Discover(context.Background())
	if err == nil {
		t.Fatal("expected discover to fail against the broken server")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("adapter leaked the one-time secret in an error: %v", err)
	}
	if !strings.Contains(err.Error(), "redacted") {
		t.Fatalf("error does not carry the redaction marker: %v", err)
	}
}

func TestGCPAdapterConstructorValidation(t *testing.T) {
	if _, err := NewGCPAdapter(GCPAdapterConfig{KeyJSON: gcpKeyJSONForTest(t)}); err == nil {
		t.Fatal("constructor accepted a missing project id")
	}
	if _, err := NewGCPAdapter(GCPAdapterConfig{ProjectID: fakeGCPProject}); err == nil {
		t.Fatal("constructor accepted missing key json")
	}
	adapter, err := NewGCPAdapter(GCPAdapterConfig{ProjectID: fakeGCPProject, KeyJSON: gcpKeyJSONForTest(t)})
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	defer adapter.Close()
	if adapter.region != "us-central1" || adapter.iamBaseURL != "https://iam.googleapis.com/v1" {
		t.Fatalf("defaults not applied: region=%q base=%q", adapter.region, adapter.iamBaseURL)
	}
}
