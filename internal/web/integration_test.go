package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mutandae/mutandae/internal/lifecycle"
	"github.com/mutandae/mutandae/pkg/protocol"
)

type fakeIntegration struct {
	connectRequest protocol.AzureIntegrationRequest
}

func (f *fakeIntegration) Requirements() protocol.AzureIntegrationRequirements {
	return protocol.AzureIntegrationRequirements{GraphApplicationPermission: "Application.ReadWrite.OwnedBy", GraphOperations: []string{"create applications"}, VaultOptional: true, Warnings: []string{"invalidate after use"}}
}
func (f *fakeIntegration) Close() {}
func (f *fakeIntegration) Connect(_ context.Context, req protocol.AzureIntegrationRequest, _, _ string, now time.Time) (protocol.AzureIntegrationSession, string, error) {
	f.connectRequest = req
	return protocol.AzureIntegrationSession{ID: "session-1", TenantHint: "ten…nant", ClientHint: "1111…1111", ExpiresAt: now.Add(time.Minute)}, "csrf-2", nil
}
func (f *fakeIntegration) Disconnect(string) {}
func (f *fakeIntegration) SessionView(string, string, time.Time) (protocol.AzureIntegrationSession, error) {
	return protocol.AzureIntegrationSession{ID: "session-1"}, nil
}
func (f *fakeIntegration) ListApplications(context.Context, string, string, time.Time) ([]protocol.AzureApplication, *protocol.OperationReceipt, error) {
	return []protocol.AzureApplication{}, nil, nil
}
func (f *fakeIntegration) CreateApplication(context.Context, string, string, protocol.AzureApplicationCreateRequest, time.Time) (protocol.AzureApplication, protocol.OperationReceipt, error) {
	return protocol.AzureApplication{ObjectID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, protocol.OperationReceipt{ID: "evt"}, nil
}
func (f *fakeIntegration) CreateSecret(context.Context, string, string, protocol.AzureSecretCreateRequest, time.Time) (protocol.AzureSecretResult, protocol.OperationReceipt, error) {
	return protocol.AzureSecretResult{SecretText: "one-time-secret", OneTime: true}, protocol.OperationReceipt{ID: "evt"}, nil
}
func (f *fakeIntegration) ReadSecret(context.Context, string, string, protocol.AzureSecretReadRequest, time.Time) (protocol.AzureSecretResult, protocol.OperationReceipt, error) {
	return protocol.AzureSecretResult{SecretText: "vault-secret", OneTime: true}, protocol.OperationReceipt{ID: "evt"}, nil
}
func (f *fakeIntegration) InvalidateSecret(context.Context, string, string, protocol.AzureSecretInvalidateRequest, time.Time) (protocol.AzureCredential, protocol.OperationReceipt, error) {
	return protocol.AzureCredential{KeyID: "key"}, protocol.OperationReceipt{ID: "evt"}, nil
}

func TestIntegrationConfigurationAndCSRFBoundary(t *testing.T) {
	integration := &fakeIntegration{}
	store := testStore(t)
	handler, err := NewServer(Dependencies{Lifecycle: store, Configuration: testConfiguration{}, Integration: integration, Clock: func() time.Time { return testNow() }, Logger: testLogger{}})
	if err != nil {
		t.Fatal(err)
	}
	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/configuration", nil))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "Application.ReadWrite.OwnedBy") || !strings.Contains(page.Body.String(), "invalidate this client secret") {
		t.Fatalf("configuration page = %d %s", page.Code, page.Body.String())
	}
	if strings.Contains(page.Body.String(), "one-time-secret") || strings.Contains(page.Body.String(), "client_secret\" value") {
		t.Fatal("configuration page exposed secret material")
	}
	cookie := page.Result().Cookies()[0]
	body := `{"tenant_id":"tenant-1","client_id":"11111111-1111-4111-8111-111111111111","client_secret":"customer-secret"}`
	withoutCSRF := httptest.NewRequest(http.MethodPost, "/api/v1/integration/connect", strings.NewReader(body))
	withoutCSRF.AddCookie(cookie)
	blocked := httptest.NewRecorder()
	handler.ServeHTTP(blocked, withoutCSRF)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("connect without header = %d, want 403", blocked.Code)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/integration/connect", strings.NewReader(body))
	request.Header.Set("X-Forwarded-Proto", "https")
	request.AddCookie(cookie)
	request.Header.Set("X-Mutandae-CSRF", cookie.Value)
	connected := httptest.NewRecorder()
	handler.ServeHTTP(connected, request)
	if connected.Code != http.StatusOK {
		t.Fatalf("connect = %d: %s", connected.Code, connected.Body.String())
	}
	if strings.Contains(connected.Body.String(), "customer-secret") || strings.Contains(connected.Body.String(), "tenant-1") {
		t.Fatal("connect response leaked credential or full tenant")
	}
	if integration.connectRequest.ClientSecret != "customer-secret" {
		t.Fatal("fake did not receive the submitted credential")
	}
	var response protocol.AzureIntegrationResponse
	if err := json.Unmarshal(connected.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Session.TenantHint != "ten…nant" {
		t.Fatalf("session hint = %q", response.Session.TenantHint)
	}
}

func TestSecurityHeadersAndNoCache(t *testing.T) {
	recorder := httptest.NewRecorder()
	testHandler(t).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/configuration", nil))
	if recorder.Header().Get("Content-Security-Policy") == "" || recorder.Header().Get("X-Content-Type-Options") != "nosniff" || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("security headers = %#v", recorder.Header())
	}
}

var _ lifecycle.IntegrationService = (*fakeIntegration)(nil)
