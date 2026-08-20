package lifecycle

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

func TestIntegrationManagerSessionSecurityAndRedactedEvents(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 3600})
		case strings.Contains(r.URL.Path, "servicePrincipals"):
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"})
		case strings.Contains(r.URL.Path, "applications(appId="):
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	// Rewrite official Microsoft destinations to the local test server without
	// changing production endpoint constants.
	transport := rewriteTransport{base: server.URL, next: http.DefaultTransport}
	client := &http.Client{Transport: transport, Timeout: time.Second}
	publisher := &MemoryEventPublisher{}
	manager, err := NewIntegrationManager(publisher, client, func() time.Time { return fixed }, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	csrf := "initial-csrf"
	session, sessionCSRF, err := manager.Connect(context.Background(), protocol.AzureIntegrationRequest{TenantID: "tenant", ClientID: "11111111-1111-4111-8111-111111111111", ClientSecret: "client-secret"}, csrf, "127.0.0.1", fixed)
	if err != nil {
		t.Fatal(err)
	}
	if session.TenantHint == "tenant" || session.ClientHint == "11111111-1111-4111-8111-111111111111" || sessionCSRF == "" {
		t.Fatalf("session leaked or failed to issue CSRF token: %+v", session)
	}
	if _, err := manager.SessionView(session.ID, "wrong", fixed); err != ErrIntegrationCSRF {
		t.Fatalf("invalid CSRF error = %v", err)
	}
	if _, err := manager.SessionView(session.ID, sessionCSRF, fixed.Add(2*time.Minute)); err != ErrIntegrationSessionNotFound {
		t.Fatalf("expired session error = %v", err)
	}
	manager.Close()
	for _, event := range publisher.Events {
		encoded, _ := json.Marshal(event)
		if strings.Contains(string(encoded), "client-secret") || strings.Contains(string(encoded), "secretText") {
			t.Fatalf("event leaked credential material: %s", encoded)
		}
	}
	if err := validateIntegrationEvent(protocol.AzureIntegrationEvent{Details: map[string]string{"vault_secret_name": "mutandae-app-key"}}); err != nil {
		t.Fatalf("safe vault reference rejected: %v", err)
	}
	if err := validateIntegrationEvent(protocol.AzureIntegrationEvent{Details: map[string]string{"secret_text": "never"}}); err == nil {
		t.Fatal("secret_text detail was accepted")
	}
}

type rewriteTransport struct {
	base string
	next http.RoundTripper
}

func (t rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(strings.TrimPrefix(t.base, "http://"), "https://")
	return t.next.RoundTrip(clone)
}
