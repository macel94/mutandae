package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

func TestKeyVaultStoreAndReadVersionedSecret(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	var stored map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tenant/oauth2/v2.0/token" {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "vault-token", "expires_in": 3600})
			return
		}
		if r.Method == http.MethodPut {
			if err := json.NewDecoder(r.Body).Decode(&stored); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "https://vault.vault.azure.net/secrets/mutandae-id-key/version12345678901234567890123456789012", "version": "version12345678901234567890123456789012", "tags": stored["tags"]})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "https://vault.vault.azure.net/secrets/mutandae-id-key/version12345678901234567890123456789012", "version": "version12345678901234567890123456789012", "value": "vault-value", "tags": stored["tags"]})
	}))
	defer server.Close()
	azure, err := NewAzureClient(protocol.AzureIntegrationRequest{TenantID: "tenant", ClientID: "11111111-1111-4111-8111-111111111111", ClientSecret: "secret"}, server.Client(), func() time.Time { return fixed })
	if err != nil {
		t.Fatal(err)
	}
	azure.loginBaseURL = server.URL
	defer azure.Close()
	config := protocol.VaultConfiguration{URL: "https://vault.vault.azure.net", SecretPrefix: "mutandae"}
	vault, err := NewKeyVaultClient(config, azure, server.Client(), func() time.Time { return fixed })
	if err != nil {
		t.Fatal(err)
	}
	// Override the validated production endpoint only after URL validation.
	vault.baseURL = server.URL
	ref, err := vault.Store(context.Background(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "vault-value", fixed.Add(90*24*time.Hour), []string{"cccccccc-cccc-4ccc-8ccc-cccccccccccc"})
	if err != nil {
		t.Fatal(err)
	}
	if ref.Version == "" || ref.SecretName == "" || len(ref.OwnerObjectIDs) != 1 {
		t.Fatalf("reference = %+v", ref)
	}
	if stored["value"] != "vault-value" {
		t.Fatalf("stored body missing value: %+v", stored)
	}
	value, got, err := vault.Read(context.Background(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ref.Version)
	if err != nil {
		t.Fatal(err)
	}
	if value != "vault-value" || got.Version != ref.Version || len(got.OwnerObjectIDs) != 1 {
		t.Fatalf("read = %q, %+v", value, got)
	}
	if _, _, err := vault.Read(context.Background(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "bad/version"); err == nil {
		t.Fatal("invalid vault version was accepted")
	}
	if strings.Contains(ref.SecretName, "vault-value") {
		t.Fatal("vault value appeared in reference")
	}
	if _, err := vault.Disable(context.Background(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ref.Version); err != nil {
		t.Fatal(err)
	}
}
