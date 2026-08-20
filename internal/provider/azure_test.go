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

func TestAzureClientGraphLifecycleAndRedaction(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	secret := "temporary-client-secret-value"
	calls := make([]string, 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.URL.Path == "/tenant-1/oauth2/v2.0/token":
			if got := r.FormValue("client_secret"); got != secret {
				t.Errorf("token client_secret = %q, want supplied secret", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "graph-token", "expires_in": 3600})
		case strings.HasPrefix(r.URL.Path, "/v1.0/servicePrincipals"):
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"})
		case r.URL.Path == "/v1.0/applications":
			if r.Method == http.MethodPost {
				_ = json.NewEncoder(w).Encode(map[string]any{"id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "appId": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "displayName": "created"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{
				map[string]any{"id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "appId": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "displayName": "owned", "passwordCredentials": []any{}},
				map[string]any{"id": "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "appId": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", "displayName": "other", "passwordCredentials": []any{}},
			}})
		case strings.HasPrefix(r.URL.Path, "/v1.0/applications(appId='"):
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "appId": "11111111-1111-4111-8111-111111111111"})
		case strings.HasSuffix(r.URL.Path, "/owners"):
			if strings.Contains(r.URL.Path, "bbbbbbbb") {
				_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{map[string]string{"id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}}})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{map[string]string{"id": "ffffffff-ffff-4fff-8fff-ffffffffffff"}}})
			}
		case strings.HasSuffix(r.URL.Path, "/addPassword"):
			_ = json.NewEncoder(w).Encode(map[string]any{"keyId": "12121212-1212-4121-8121-121212121212", "displayName": "demo", "secretText": "generated-secret", "startDateTime": fixed, "endDateTime": fixed.Add(90 * 24 * time.Hour), "hint": "ret"})
		case strings.HasSuffix(r.URL.Path, "/removePassword"):
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewAzureClient(protocol.AzureIntegrationRequest{TenantID: "tenant-1", ClientID: "11111111-1111-4111-8111-111111111111", ClientSecret: secret}, server.Client(), func() time.Time { return fixed })
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// Test endpoint replacement is scoped to this client and cannot race other tests.
	client.loginBaseURL, client.graphBaseURL = server.URL, server.URL+"/v1.0"
	if err := client.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	app, err := client.CreateApplication(context.Background(), protocol.AzureApplicationCreateRequest{DisplayName: "created"})
	if err != nil {
		t.Fatal(err)
	}
	if !app.OwnedByCallingClient {
		t.Fatal("created application was not marked owned")
	}
	result, err := client.CreateSecret(context.Background(), protocol.AzureSecretCreateRequest{ApplicationObjectID: app.ObjectID, DisplayName: "demo", ExpiresAt: fixed.Add(90 * 24 * time.Hour)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.SecretText != "generated-secret" || !result.OneTime {
		t.Fatalf("secret result = %+v", result)
	}
	if err := client.RemoveSecret(context.Background(), app.ObjectID, result.Credential.KeyID); err != nil {
		t.Fatal(err)
	}
	if err := client.ensureOwned(context.Background(), "dddddddd-dddd-4ddd-8ddd-dddddddddddd"); err == nil {
		t.Fatal("mutation was allowed for an unowned application")
	}
	joined := strings.Join(calls, "\n")
	if strings.Contains(joined, secret) {
		t.Fatal("secret appeared in request path")
	}
	if got := redactError("failed "+secret, secret).Error(); strings.Contains(got, secret) {
		t.Fatal("redactError leaked client secret")
	}
}

func TestAzureClientRejectsUnsafeVault(t *testing.T) {
	client, err := NewAzureClient(protocol.AzureIntegrationRequest{TenantID: "tenant", ClientID: "11111111-1111-4111-8111-111111111111", ClientSecret: "secret"}, http.DefaultClient, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewKeyVaultClient(protocol.VaultConfiguration{URL: "http://vault.vault.azure.net"}, client, http.DefaultClient, time.Now)
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("unsafe vault error = %v", err)
	}
}
