package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

type gcpSecretRequestHandler func(http.ResponseWriter, *http.Request, []byte)

func newGCPSecretTestServer(t *testing.T, fixed time.Time, handler gcpSecretRequestHandler, secretManager bool) (*httptest.Server, *GCPAdapter) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			assertGCPTokenRequest(t, r, fixed)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "ya29.gcp-secret-test-token",
				"expires_in":   3600,
				"token_type":   "Bearer",
			})
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer ya29.gcp-secret-test-token" {
			t.Errorf("Secret Manager authorization = %q, want bearer test token", got)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read Secret Manager request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		handler(w, r, body)
	}))
	adapter, err := NewGCPAdapter(GCPAdapterConfig{
		ProjectID:            fakeGCPProject,
		Region:               "us-central1",
		KeyJSON:              gcpKeyJSONForTest(t),
		TokenURI:             server.URL + "/token",
		SecretManager:        secretManager,
		SecretManagerBaseURL: server.URL + "/v1",
		HTTPClient:           server.Client(),
		Now:                  func() time.Time { return fixed },
	})
	if err != nil {
		server.Close()
		t.Fatalf("NewGCPAdapter() error = %v", err)
	}
	return server, adapter
}

func assertGCPTokenRequest(t *testing.T, r *http.Request, fixed time.Time) {
	t.Helper()
	if err := r.ParseForm(); err != nil {
		t.Errorf("parse token request: %v", err)
		return
	}
	if got := r.Form.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		t.Errorf("grant_type = %q", got)
	}
	parts := strings.Split(r.Form.Get("assertion"), ".")
	if len(parts) != 3 {
		t.Errorf("JWT assertion has %d parts, want 3", len(parts))
		return
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Errorf("decode JWT claims: %v", err)
		return
	}
	var claims struct {
		IssuedAt int64  `json:"iat"`
		Expires  int64  `json:"exp"`
		Scope    string `json:"scope"`
	}
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		t.Errorf("decode JWT claims JSON: %v", err)
		return
	}
	if claims.IssuedAt != fixed.Unix() {
		t.Errorf("JWT iat = %d, want %d", claims.IssuedAt, fixed.Unix())
	}
	if claims.Expires != fixed.Add(time.Hour).Unix() {
		t.Errorf("JWT exp = %d, want %d", claims.Expires, fixed.Add(time.Hour).Unix())
	}
	if claims.Scope != gcpIAMScope {
		t.Errorf("JWT scope = %q, want %q", claims.Scope, gcpIAMScope)
	}
}

func readGCPSecretJSON(t *testing.T, body []byte, output any) {
	t.Helper()
	if err := json.Unmarshal(body, output); err != nil {
		t.Errorf("decode Secret Manager request JSON: %v; body=%s", err, body)
	}
}

func demoGCPIdentity(name string, expiresAt time.Time) protocol.MachineIdentity {
	return protocol.MachineIdentity{
		Name:      name,
		ExpiresAt: expiresAt,
		Provider:  protocol.ProviderBinding{Provider: gcpKind, ProjectID: fakeGCPProject},
	}
}

func TestGCPSecretStoreHappyPath(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	identity := demoGCPIdentity("mutandae-demo-store", fixed.Add(90*24*time.Hour))
	secret := "private-value-42"
	var calls int
	server, adapter := newGCPSecretTestServer(t, fixed, func(w http.ResponseWriter, r *http.Request, body []byte) {
		calls++
		wantPath := "/v1/projects/" + fakeGCPProject + "/secrets/" + identity.Name + ":addVersion"
		if r.Method != http.MethodPost || r.URL.Path != wantPath {
			t.Errorf("request = %s %s, want POST %s", r.Method, r.URL.Path, wantPath)
		}
		var request struct {
			Payload struct {
				Data string `json:"data"`
			} `json:"payload"`
		}
		readGCPSecretJSON(t, body, &request)
		decoded, err := base64.StdEncoding.DecodeString(request.Payload.Data)
		if err != nil {
			t.Errorf("decode stored payload: %v", err)
		}
		if string(decoded) != secret {
			t.Errorf("stored secret = %q, want %q", decoded, secret)
		}
		if strings.Contains(string(body), secret) {
			t.Errorf("request body contains cleartext secret: %s", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"name": "projects/" + fakeGCPProject + "/secrets/" + identity.Name + "/versions/7",
		})
	}, true)
	defer server.Close()

	ref, err := adapter.StoreSecret(context.Background(), identity, "key-1", secret)
	if err != nil {
		t.Fatalf("StoreSecret() error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("Secret Manager calls = %d, want 1", calls)
	}
	if ref.URL != server.URL+"/v1" || ref.SecretName != identity.Name || ref.Version != "7" || !ref.ExpiresAt.Equal(identity.ExpiresAt) {
		t.Fatalf("reference = %+v", ref)
	}
	if strings.Contains(fmt.Sprintf("%+v", ref), secret) {
		t.Fatalf("secret appeared in reference: %+v", ref)
	}
}

// TestGCPSecretStoreSanitizesEmailIdentityNames pins the delivery contract for
// real provisioned GCP identities: their names are service-account emails,
// which are not valid Secret Manager secret ids, so the adapter derives a
// deterministic sanitized id and still delivers under audit.
func TestGCPSecretStoreSanitizesEmailIdentityNames(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	identity := demoGCPIdentity("mutandae-demo-four-va-f55979e8@mutandae-demo.iam.gserviceaccount.com", fixed.Add(90*24*time.Hour))
	wantID := "mutandae-demo-four-va-f55979e8-mutandae-demo-iam-gserviceaccount-com"
	var sawID string
	server, adapter := newGCPSecretTestServer(t, fixed, func(w http.ResponseWriter, r *http.Request, body []byte) {
		sawID = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]string{
			"name": "projects/" + fakeGCPProject + "/secrets/" + wantID + "/versions/1",
		})
	}, true)
	defer server.Close()

	ref, err := adapter.StoreSecret(context.Background(), identity, "key-1", "email-name-secret")
	if err != nil {
		t.Fatalf("StoreSecret() error = %v", err)
	}
	if !strings.Contains(sawID, "/secrets/"+wantID+":addVersion") {
		t.Fatalf("secret id path = %q, want the sanitized id %q", sawID, wantID)
	}
	if ref.SecretName != wantID {
		t.Fatalf("ref.SecretName = %q, want %q", ref.SecretName, wantID)
	}
}

func TestGCPSanitizeSecretID(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"mutandae-demo-four-va-f55979e8@mutandae-demo.iam.gserviceaccount.com", "mutandae-demo-four-va-f55979e8-mutandae-demo-iam-gserviceaccount-com"},
		{"mutandae-demo-plain", "mutandae-demo-plain"},
		{"mutandae-demo--trailing--", "mutandae-demo--trailing"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := gcpSanitizeSecretID(tc.in); got != tc.want {
			t.Errorf("gcpSanitizeSecretID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestGCPSecretStoreCreatesMissingSecretAndRetries(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	identity := demoGCPIdentity("mutandae-demo-fallback", fixed.Add(24*time.Hour))
	secret := "fallback-secret"
	var calls []string
	server, adapter := newGCPSecretTestServer(t, fixed, func(w http.ResponseWriter, r *http.Request, body []byte) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		addPath := "/v1/projects/" + fakeGCPProject + "/secrets/" + identity.Name + ":addVersion"
		createPath := "/v1/projects/" + fakeGCPProject + "/secrets"
		switch {
		case r.Method == http.MethodPost && r.URL.Path == addPath && len(calls) == 1:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{"code": 404, "status": "NOT_FOUND", "message": "not found"},
			})
		case r.Method == http.MethodPost && r.URL.Path == createPath:
			if got := r.URL.Query().Get("secretId"); got != identity.Name {
				t.Errorf("secretId = %q, want %q", got, identity.Name)
			}
			var request struct {
				Replication struct {
					Automatic map[string]any `json:"automatic"`
				} `json:"replication"`
				Labels map[string]string `json:"labels"`
			}
			readGCPSecretJSON(t, body, &request)
			if request.Replication.Automatic == nil || request.Labels["mutandae"] != "demo" {
				t.Errorf("create body = %+v, want automatic replication and demo label", request)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"name": createPath})
		case r.Method == http.MethodPost && r.URL.Path == addPath:
			var request struct {
				Payload struct {
					Data string `json:"data"`
				} `json:"payload"`
			}
			readGCPSecretJSON(t, body, &request)
			decoded, err := base64.StdEncoding.DecodeString(request.Payload.Data)
			if err != nil || string(decoded) != secret {
				t.Errorf("retried payload = %q, decode error = %v", decoded, err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"name": "projects/" + fakeGCPProject + "/secrets/" + identity.Name + "/versions/2",
			})
		default:
			t.Errorf("unexpected Secret Manager request %s %s", r.Method, r.URL.RequestURI())
			http.NotFound(w, r)
		}
	}, true)
	defer server.Close()

	ref, err := adapter.StoreSecret(context.Background(), identity, "key-2", secret)
	if err != nil {
		t.Fatalf("StoreSecret() fallback error = %v", err)
	}
	if len(calls) != 3 || !strings.Contains(calls[0], ":addVersion") || !strings.Contains(calls[1], "?secretId=") || !strings.Contains(calls[2], ":addVersion") {
		t.Fatalf("request sequence = %v", calls)
	}
	if ref.Version != "2" || ref.SecretName != identity.Name {
		t.Fatalf("reference = %+v", ref)
	}
}

func TestGCPSecretReadRoundTrip(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	identity := demoGCPIdentity("mutandae-demo-read", fixed.Add(48*time.Hour))
	secret := "read-back-secret"
	server, adapter := newGCPSecretTestServer(t, fixed, func(w http.ResponseWriter, r *http.Request, body []byte) {
		wantPath := "/v1/projects/" + fakeGCPProject + "/secrets/" + identity.Name + "/versions/3:access"
		if r.Method != http.MethodGet || r.URL.Path != wantPath || len(body) != 0 {
			t.Errorf("request = %s %s body=%q, want GET %s with no body", r.Method, r.URL.Path, body, wantPath)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":    "projects/" + fakeGCPProject + "/secrets/" + identity.Name + "/versions/3",
			"payload": map[string]string{"data": base64.StdEncoding.EncodeToString([]byte(secret))},
		})
	}, true)
	defer server.Close()

	value, ref, err := adapter.ReadSecret(context.Background(), identity, "key-3", "3")
	if err != nil {
		t.Fatalf("ReadSecret() error = %v", err)
	}
	if value != secret {
		t.Fatalf("ReadSecret() value = %q, want %q", value, secret)
	}
	if ref.SecretName != identity.Name || ref.Version != "3" || !ref.ExpiresAt.Equal(identity.ExpiresAt) {
		t.Fatalf("reference = %+v", ref)
	}
}

func TestGCPSecretRevokeDisablesAndIsIdempotent(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	identity := demoGCPIdentity("mutandae-demo-revoke", fixed.Add(72*time.Hour))
	var calls int
	server, adapter := newGCPSecretTestServer(t, fixed, func(w http.ResponseWriter, r *http.Request, body []byte) {
		calls++
		wantPath := "/v1/projects/" + fakeGCPProject + "/secrets/" + identity.Name + "/versions/latest:disable"
		if r.Method != http.MethodPost || r.URL.Path != wantPath || len(body) != 0 {
			t.Errorf("request = %s %s body=%q, want POST %s with no body", r.Method, r.URL.Path, body, wantPath)
		}
		if calls == 1 {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"name": "projects/" + fakeGCPProject + "/secrets/" + identity.Name + "/versions/5",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{"code": 404, "status": "NOT_FOUND", "message": "not found"},
		})
	}, true)
	defer server.Close()

	first, err := adapter.RevokeSecret(context.Background(), identity, "key-4")
	if err != nil {
		t.Fatalf("first RevokeSecret() error = %v", err)
	}
	second, err := adapter.RevokeSecret(context.Background(), identity, "key-4")
	if err != nil {
		t.Fatalf("idempotent RevokeSecret() error = %v", err)
	}
	if first.Version != "5" || second.Version != "latest" || calls != 2 {
		t.Fatalf("first=%+v second=%+v calls=%d", first, second, calls)
	}
}

func TestGCPSecretCapabilityDisabled(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	server, adapter := newGCPSecretTestServer(t, fixed, func(w http.ResponseWriter, r *http.Request, body []byte) {
		t.Errorf("disabled adapter made request %s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}, false)
	defer server.Close()
	identity := demoGCPIdentity("mutandae-demo-disabled", fixed)

	if _, err := adapter.StoreSecret(context.Background(), identity, "key", "secret"); !errors.Is(err, ErrVaultUnsupported) {
		t.Errorf("StoreSecret() error = %v, want ErrVaultUnsupported", err)
	}
	if _, _, err := adapter.ReadSecret(context.Background(), identity, "key", "latest"); !errors.Is(err, ErrVaultUnsupported) {
		t.Errorf("ReadSecret() error = %v, want ErrVaultUnsupported", err)
	}
	if _, err := adapter.RevokeSecret(context.Background(), identity, "key"); !errors.Is(err, ErrVaultUnsupported) {
		t.Errorf("RevokeSecret() error = %v, want ErrVaultUnsupported", err)
	}
}

func TestGCPSecretRejectsNonDemoIdentity(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	server, adapter := newGCPSecretTestServer(t, fixed, func(w http.ResponseWriter, r *http.Request, body []byte) {
		t.Errorf("non-demo identity made request %s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}, true)
	defer server.Close()
	identity := demoGCPIdentity("production-service-account", fixed)

	checks := []struct {
		name string
		call func() error
	}{
		{name: "store", call: func() error {
			_, err := adapter.StoreSecret(context.Background(), identity, "key", "secret")
			return err
		}},
		{name: "read", call: func() error {
			_, _, err := adapter.ReadSecret(context.Background(), identity, "key", "latest")
			return err
		}},
		{name: "revoke", call: func() error {
			_, err := adapter.RevokeSecret(context.Background(), identity, "key")
			return err
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			err := check.call()
			if err == nil || !strings.Contains(err.Error(), "mutandae-demo-*") {
				t.Fatalf("error = %v, want mutandae-demo-* namespace error", err)
			}
		})
	}
}
