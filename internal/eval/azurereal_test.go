//go:build realclouds

package eval

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// azureRealtime returns the Entra client credentials supplied by the reviewer,
// or false when this part of the eval should be skipped.
func azureRealtime() (tenantID, clientID, clientSecret string, ok bool) {
	if !realCloudEnabled() {
		return "", "", "", false
	}
	tenantID = os.Getenv("AZURE_TENANT_ID")
	clientID = os.Getenv("AZURE_CLIENT_ID")
	clientSecret = os.Getenv("AZURE_CLIENT_SECRET")
	return tenantID, clientID, clientSecret, tenantID != "" && clientID != "" && clientSecret != ""
}

// cookieJar records the session/CSRF cookies set by the configuration page and
// connect endpoint so state-changing integration calls can replay them.
type cookieJar struct {
	cookies map[string]string
}

func newCookieJar() *cookieJar { return &cookieJar{cookies: map[string]string{}} }

func (j *cookieJar) capture(resp *http.Response) {
	for _, cookie := range resp.Cookies() {
		j.cookies[cookie.Name] = cookie.Value
	}
}

func (j *cookieJar) apply(req *http.Request) {
	for name, value := range j.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
}

func (j *cookieJar) csrf() string { return j.cookies["mutandae_csrf"] }

func azureJSON(t *testing.T, server *httptest.Server, jar *cookieJar, method, path string, body any) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal %s %s: %v", method, path, err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, server.URL+path, reader)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, path, err)
	}
	req.Header.Set("Accept", protocol.MediaType)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Content-Type", "application/json")
	if jar != nil {
		jar.apply(req)
		if jar.csrf() != "" && (method != http.MethodGet || path != "/api/v1/integration/connect") {
			req.Header.Set("X-Mutandae-CSRF", jar.csrf())
		}
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	if jar != nil {
		jar.capture(resp)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		t.Fatalf("%s %s: read: %v", method, path, err)
	}
	t.Logf("%s %s -> %d", method, path, resp.StatusCode)
	return resp.StatusCode, data
}

// TestAzureRealIntegrationExtension evaluates the interactive Azure / Entra
// extension (issue #4, Azure-only checklist): requirements → connect → list
// applications → create application → addPassword (one-time secret) →
// invalidate → disconnect, asserting redacted receipts throughout. It requires
// a real AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET with
// Application.ReadWrite.OwnedBy admin-consented.
func TestAzureRealIntegrationExtension(t *testing.T) {
	tenantID, clientID, clientSecret, ok := azureRealtime()
	if !ok {
		t.Skip("AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET not set")
	}
	if strings.Contains(clientSecret, "tenantID") || strings.Contains(clientSecret, "clientID") {
		t.Fatal("azure credentials look like unsubstituted templates")
	}
	server, _ := bootServer(t)

	jar := newCookieJar()

	// Requirements are non-secret and must be obtainable before connecting.
	status, data := azureJSON(t, server, nil, http.MethodGet, "/api/v1/integration/requirements", nil)
	if status != http.StatusOK {
		t.Fatalf("requirements status = %d: %s", status, data)
	}
	var requirementsResp protocol.AzureIntegrationRequirementsResponse
	if err := json.Unmarshal(data, &requirementsResp); err != nil {
		t.Fatalf("decode requirements: %v", err)
	}
	requirements := requirementsResp.Requirements
	if requirements.GraphApplicationPermission != "Application.ReadWrite.OwnedBy" {
		t.Fatalf("requirements permission = %q, want Application.ReadWrite.OwnedBy", requirements.GraphApplicationPermission)
	}
	assertNoSecrets(t, "requirements", data)

	// Load the configuration page to obtain a CSRF cookie.
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/configuration", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("configuration: %v", err)
	}
	jar.capture(resp)
	_ = resp.Body.Close()
	if jar.csrf() == "" {
		t.Fatal("configuration page did not issue a CSRF cookie")
	}

	// Connect with the real client credentials.
	status, data = azureJSON(t, server, jar, http.MethodPost, "/api/v1/integration/connect", map[string]any{
		"tenant_id": tenantID, "client_id": clientID, "client_secret": clientSecret,
	})
	if status != http.StatusOK {
		t.Fatalf("connect status = %d: %s", status, data)
	}
	var connected protocol.AzureIntegrationResponse
	if err := json.Unmarshal(data, &connected); err != nil {
		t.Fatalf("decode connect: %v", err)
	}
	if connected.Session.ID == "" || connected.Session.TenantHint == "" {
		t.Fatalf("connect session incomplete: %+v", connected.Session)
	}
	if strings.Contains(string(data), clientSecret) || strings.Contains(string(data), tenantID) {
		t.Fatal("connect response leaked the client secret or full tenant id")
	}
	assertNoSecrets(t, "connect response", data)

	// List owned applications.
	status, data = azureJSON(t, server, jar, http.MethodGet, "/api/v1/integration/applications", nil)
	if status != http.StatusOK {
		t.Fatalf("applications status = %d: %s", status, data)
	}
	var apps protocol.AzureApplicationsResponse
	if err := json.Unmarshal(data, &apps); err != nil {
		t.Fatalf("decode applications: %v", err)
	}
	assertNoSecrets(t, "applications response", data)

	// Create an application owned by the calling client.
	createdName := fmt.Sprintf("mutandae-eval-%d", time.Now().Unix())
	status, data = azureJSON(t, server, jar, http.MethodPost, "/api/v1/integration/applications", map[string]any{
		"display_name": createdName,
	})
	if status != http.StatusCreated {
		t.Fatalf("create application status = %d: %s", status, data)
	}
	var createdApp protocol.AzureApplicationResponse
	if err := json.Unmarshal(data, &createdApp); err != nil {
		t.Fatalf("decode create application: %v", err)
	}
	if createdApp.Application.ObjectID == "" || !createdApp.Application.OwnedByCallingClient {
		t.Fatalf("created application is not owner-backed: %+v", createdApp.Application)
	}
	assertNoSecrets(t, "create application response", data)

	// addPassword: a one-time secret must be returned exactly once with the
	// credential key id; the receipt must be redacted.
	status, data = azureJSON(t, server, jar, http.MethodPost, "/api/v1/integration/secrets", map[string]any{
		"application_object_id": createdApp.Application.ObjectID,
		"display_name":          "eval-rotation",
	})
	if status != http.StatusCreated {
		t.Fatalf("create secret status = %d: %s", status, data)
	}
	var secretResp protocol.AzureSecretResponse
	if err := json.Unmarshal(data, &secretResp); err != nil {
		t.Fatalf("decode create secret: %v", err)
	}
	if secretResp.Secret.SecretText == "" || !secretResp.Secret.OneTime {
		t.Fatalf("addPassword did not return a one-time secret: %+v", secretResp.Secret)
	}
	if secretResp.Secret.Credential.KeyID == "" {
		t.Fatalf("addPassword returned no key_id: %+v", secretResp.Secret.Credential)
	}
	if secretResp.Receipt.Event.CorrelationID == "" || !secretResp.Receipt.EventPublished {
		t.Fatalf("create secret returned no published receipt: %+v", secretResp.Receipt)
	}
	if secretResp.Receipt.Event.CorrelationID == "" {
		t.Fatalf("create secret receipt missing correlation_id: %+v", secretResp.Receipt.Event)
	}
	assertNoSecrets(t, "create secret response", data)

	// The returned secret must never appear in the receipt event.
	receiptJSON, _ := json.Marshal(secretResp.Receipt)
	if strings.Contains(string(receiptJSON), secretResp.Secret.SecretText) {
		t.Fatal("receipt leaked the one-time secret text")
	}
	assertNoSecrets(t, "secret receipt", receiptJSON)

	// Invalidate: the Graph credential is removed; response carries key id.
	status, data = azureJSON(t, server, jar, http.MethodPost, "/api/v1/integration/secrets/invalidate", map[string]any{
		"application_object_id": createdApp.Application.ObjectID,
		"key_id":                secretResp.Secret.Credential.KeyID,
	})
	if status != http.StatusOK {
		t.Fatalf("invalidate status = %d: %s", status, data)
	}
	var invalidated protocol.AzureSecretInvalidateResponse
	if err := json.Unmarshal(data, &invalidated); err != nil {
		t.Fatalf("decode invalidate: %v", err)
	}
	if invalidated.Credential.KeyID != secretResp.Secret.Credential.KeyID {
		t.Fatalf("invalidated key id = %q, want %q", invalidated.Credential.KeyID, secretResp.Secret.Credential.KeyID)
	}
	assertNoSecrets(t, "invalidate response", data)

	// Disconnect and verify the session is cleared.
	status, data = azureJSON(t, server, jar, http.MethodPost, "/api/v1/integration/disconnect", nil)
	if status != http.StatusOK {
		t.Fatalf("disconnect status = %d: %s", status, data)
	}
	assertNoSecrets(t, "disconnect response", data)

	status, data = azureJSON(t, server, jar, http.MethodGet, "/api/v1/integration/session", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("session after disconnect = %d, want 401: %s", status, data)
	}
}
