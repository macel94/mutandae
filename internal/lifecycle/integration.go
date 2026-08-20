package lifecycle

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mutandae/mutandae/internal/provider"
	"github.com/mutandae/mutandae/pkg/protocol"
)

var (
	ErrIntegrationSessionNotFound = errors.New("integration session not found or expired")
	ErrIntegrationCSRF            = errors.New("integration session CSRF token is invalid")
	ErrIntegrationRateLimited     = errors.New("too many integration connection attempts")
)

// IntegrationService is the web layer's consumer-side boundary for the
// interactive real-tenant path. It deliberately has no List/Rotate methods
// from the persistent demo lifecycle store.
type IntegrationService interface {
	Requirements() protocol.AzureIntegrationRequirements
	Close()

	Connect(ctx context.Context, req protocol.AzureIntegrationRequest, csrf, rateKey string, now time.Time) (protocol.AzureIntegrationSession, string, error)
	Disconnect(sessionID string)
	SessionView(sessionID string, csrf string, now time.Time) (protocol.AzureIntegrationSession, error)
	ListApplications(ctx context.Context, sessionID, csrf string, now time.Time) ([]protocol.AzureApplication, *protocol.OperationReceipt, error)
	CreateApplication(ctx context.Context, sessionID, csrf string, req protocol.AzureApplicationCreateRequest, now time.Time) (protocol.AzureApplication, protocol.OperationReceipt, error)
	CreateSecret(ctx context.Context, sessionID, csrf string, req protocol.AzureSecretCreateRequest, now time.Time) (protocol.AzureSecretResult, protocol.OperationReceipt, error)
	ReadSecret(ctx context.Context, sessionID, csrf string, req protocol.AzureSecretReadRequest, now time.Time) (protocol.AzureSecretResult, protocol.OperationReceipt, error)
	InvalidateSecret(ctx context.Context, sessionID, csrf string, req protocol.AzureSecretInvalidateRequest, now time.Time) (protocol.AzureCredential, protocol.OperationReceipt, error)
}

// IntegrationSession owns the non-serializable provider client. Never add this
// type to Snapshot or a protocol response.
type IntegrationSession struct {
	ID        string
	CSRF      string
	ExpiresAt time.Time
	Client    *provider.AzureClient
	Vault     *protocol.VaultConfiguration
	VaultRefs map[string]protocol.VaultReference
	Public    protocol.AzureIntegrationSession
}

type integrationManager struct {
	mu             sync.Mutex
	sessions       map[string]*IntegrationSession
	publisher      EventPublisher
	httpClient     *http.Client
	now            func() time.Time
	ttl            time.Duration
	maxConnections int
	maxSessions    int
	connections    map[string][]time.Time
	stopCleanup    chan struct{}
	cleanupDone    chan struct{}
	closeOnce      sync.Once
}

// NewIntegrationManager creates an in-memory, TTL-bounded integration service.
// Credentials are retained only inside active provider clients and cleared on
// disconnect/expiry; no repository is accepted by this constructor.
func NewIntegrationManager(publisher EventPublisher, httpClient *http.Client, now func() time.Time, ttl time.Duration) (IntegrationService, error) {
	if publisher == nil {
		return nil, errors.New("integration event publisher is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	if now == nil {
		now = time.Now
	}
	if ttl <= 0 || ttl > 30*time.Minute {
		ttl = 10 * time.Minute
	}
	m := &integrationManager{sessions: make(map[string]*IntegrationSession), publisher: publisher, httpClient: httpClient, now: now, ttl: ttl, maxConnections: 5, maxSessions: 50, connections: make(map[string][]time.Time), stopCleanup: make(chan struct{}), cleanupDone: make(chan struct{})}
	go m.cleanupLoop()
	return m, nil
}

func (m *integrationManager) Requirements() protocol.AzureIntegrationRequirements {
	return protocol.AzureIntegrationRequirements{
		GraphApplicationPermission: "Application.ReadWrite.OwnedBy",
		GraphOperations: []string{
			"list applications and owners",
			"create applications (the creating client becomes owner where supported)",
			"addPassword and removePassword only on applications owned by the calling client",
		},
		VaultOptional:    true,
		VaultWriteRole:   "Key Vault Secrets Officer (existing vault, data plane)",
		VaultReadRole:    "Key Vault Secrets User (read only) or Secrets Officer",
		OwnerEnforcement: "Graph ownership is checked before mutation. Vault owner-only access must be enforced by Azure RBAC/delegated identity; client-credential sessions cannot identify a human owner.",
		Warnings: []string{
			"The client secret is accepted only over HTTPS and held in memory for a short session.",
			"Microsoft Graph returns a generated secret only once; without a vault you must copy it immediately.",
			"Invalidate this integration client secret in Entra ID after the demo and remove its consent if no longer needed.",
			"Mutandae never stores customer credentials, Graph tokens, or secret plaintext in Redis, snapshots, events, logs, or HTML.",
		},
	}
}

func (m *integrationManager) Connect(ctx context.Context, req protocol.AzureIntegrationRequest, csrf, rateKey string, now time.Time) (protocol.AzureIntegrationSession, string, error) {
	csrf = strings.TrimSpace(csrf)
	if csrf == "" {
		return protocol.AzureIntegrationSession{}, "", ErrIntegrationCSRF
	}
	if err := m.allowConnection(rateKey, now); err != nil {
		return protocol.AzureIntegrationSession{}, "", err
	}
	client, err := provider.NewAzureClient(req, m.httpClient, m.now)
	if err != nil {
		return protocol.AzureIntegrationSession{}, "", err
	}
	if err := client.Verify(ctx); err != nil {
		client.Close()
		return protocol.AzureIntegrationSession{}, "", err
	}
	id, err := randomID("int")
	if err != nil {
		client.Close()
		return protocol.AzureIntegrationSession{}, "", err
	}
	sessionCSRF, err := randomID("csrf")
	if err != nil {
		client.Close()
		return protocol.AzureIntegrationSession{}, "", err
	}
	now = now.UTC()
	public := protocol.AzureIntegrationSession{
		ID: id, Provider: "azure-entra", TenantHint: redactIdentifier(req.TenantID), ClientHint: redactIdentifier(req.ClientID),
		ExpiresAt: now.Add(m.ttl), VaultConfigured: req.Vault != nil,
		Capabilities: []string{"list applications", "create applications", "create one-time client secrets", "invalidate owned secrets", "Redis redacted event publication"},
	}
	session := &IntegrationSession{ID: id, CSRF: sessionCSRF, ExpiresAt: now.Add(m.ttl), Client: client, Vault: req.Vault, VaultRefs: make(map[string]protocol.VaultReference), Public: public}
	m.mu.Lock()
	if len(m.sessions) >= m.maxSessions {
		m.mu.Unlock()
		client.Close()
		return protocol.AzureIntegrationSession{}, "", ErrIntegrationRateLimited
	}
	m.sessions[id] = session
	m.mu.Unlock()
	return public, sessionCSRF, nil
}

func (m *integrationManager) Close() {
	m.closeOnce.Do(func() {
		close(m.stopCleanup)
		<-m.cleanupDone
	})
	m.mu.Lock()
	sessions := make([]*IntegrationSession, 0, len(m.sessions))
	for id, session := range m.sessions {
		sessions = append(sessions, session)
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	for _, session := range sessions {
		if session.Client != nil {
			session.Client.Close()
		}
	}
}

func (m *integrationManager) cleanupLoop() {
	interval := m.ttl / 2
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer close(m.cleanupDone)
	for {
		select {
		case <-ticker.C:
			m.expireSessions(m.now().UTC())
		case <-m.stopCleanup:
			return
		}
	}
}

func (m *integrationManager) expireSessions(now time.Time) {
	m.mu.Lock()
	expired := make([]*IntegrationSession, 0)
	for id, session := range m.sessions {
		if !now.Before(session.ExpiresAt) {
			expired = append(expired, session)
			delete(m.sessions, id)
		}
	}
	m.mu.Unlock()
	for _, session := range expired {
		if session.Client != nil {
			session.Client.Close()
		}
	}
}

func (m *integrationManager) Disconnect(sessionID string) {
	m.mu.Lock()
	session := m.sessions[sessionID]
	delete(m.sessions, sessionID)
	m.mu.Unlock()
	if session != nil && session.Client != nil {
		session.Client.Close()
	}
}

func (m *integrationManager) session(sessionID, csrf string, now time.Time) (*IntegrationSession, error) {
	m.mu.Lock()
	session := m.sessions[sessionID]
	if session == nil {
		m.mu.Unlock()
		return nil, ErrIntegrationSessionNotFound
	}
	if !now.UTC().Before(session.ExpiresAt) {
		delete(m.sessions, sessionID)
		m.mu.Unlock()
		session.Client.Close()
		return nil, ErrIntegrationSessionNotFound
	}
	if !secureEqual(session.CSRF, csrf) {
		m.mu.Unlock()
		return nil, ErrIntegrationCSRF
	}
	m.mu.Unlock()
	return session, nil
}

func (m *integrationManager) SessionView(sessionID, csrf string, now time.Time) (protocol.AzureIntegrationSession, error) {
	session, err := m.session(sessionID, csrf, now)
	if err != nil {
		return protocol.AzureIntegrationSession{}, err
	}
	return session.Public, nil
}

func (m *integrationManager) ListApplications(ctx context.Context, sessionID, csrf string, now time.Time) ([]protocol.AzureApplication, *protocol.OperationReceipt, error) {
	session, err := m.session(sessionID, csrf, now)
	if err != nil {
		return nil, nil, err
	}
	applications, err := session.Client.ListApplications(ctx)
	if err != nil {
		return nil, nil, err
	}
	m.mu.Lock()
	for i := range applications {
		for j := range applications[i].Credentials {
			if ref, ok := session.VaultRefs[vaultRefKey(applications[i].ObjectID, applications[i].Credentials[j].KeyID)]; ok {
				copy := ref
				applications[i].Credentials[j].Vault = &copy
			}
		}
	}
	m.mu.Unlock()
	receipt, err := m.receipt(ctx, protocol.EventIntegrationConnected, session, "", map[string]string{"operation": "list_applications"}, now)
	return applications, &receipt, err
}

func (m *integrationManager) CreateApplication(ctx context.Context, sessionID, csrf string, req protocol.AzureApplicationCreateRequest, now time.Time) (protocol.AzureApplication, protocol.OperationReceipt, error) {
	session, err := m.session(sessionID, csrf, now)
	if err != nil {
		return protocol.AzureApplication{}, protocol.OperationReceipt{}, err
	}
	application, err := session.Client.CreateApplication(ctx, req)
	if err != nil {
		return protocol.AzureApplication{}, protocol.OperationReceipt{}, err
	}
	receipt, err := m.receipt(ctx, protocol.EventApplicationCreated, session, application.ObjectID, map[string]string{"display_name": application.DisplayName}, now)
	return application, receipt, err
}

func (m *integrationManager) CreateSecret(ctx context.Context, sessionID, csrf string, req protocol.AzureSecretCreateRequest, now time.Time) (protocol.AzureSecretResult, protocol.OperationReceipt, error) {
	session, err := m.session(sessionID, csrf, now)
	if err != nil {
		return protocol.AzureSecretResult{}, protocol.OperationReceipt{}, err
	}
	var vault *protocol.VaultConfiguration
	if req.StoreInVault {
		vault = session.Vault
		if vault == nil {
			return protocol.AzureSecretResult{}, protocol.OperationReceipt{}, errors.New("store_in_vault requires a configured Key Vault")
		}
	}
	result, err := session.Client.CreateSecret(ctx, req, vault)
	if err != nil {
		return protocol.AzureSecretResult{}, protocol.OperationReceipt{}, err
	}
	if result.Vault != nil {
		m.mu.Lock()
		session.VaultRefs[vaultRefKey(req.ApplicationObjectID, result.Credential.KeyID)] = *result.Vault
		m.mu.Unlock()
	}
	details := map[string]string{"key_id": result.Credential.KeyID, "stored_in_vault": fmt.Sprint(result.Vault != nil)}
	if result.Vault != nil {
		details["vault_secret_name"] = result.Vault.SecretName
		details["vault_version"] = result.Vault.Version
	}
	receipt, err := m.receipt(ctx, protocol.EventSecretCreated, session, req.ApplicationObjectID, details, now)
	return result, receipt, err
}

func (m *integrationManager) ReadSecret(ctx context.Context, sessionID, csrf string, req protocol.AzureSecretReadRequest, now time.Time) (protocol.AzureSecretResult, protocol.OperationReceipt, error) {
	session, err := m.session(sessionID, csrf, now)
	if err != nil {
		return protocol.AzureSecretResult{}, protocol.OperationReceipt{}, err
	}
	if req.Version == "" {
		m.mu.Lock()
		if ref, ok := session.VaultRefs[vaultRefKey(req.ApplicationObjectID, req.KeyID)]; ok {
			req.Version = ref.Version
		}
		m.mu.Unlock()
	}
	result, err := session.Client.ReadSecret(ctx, req)
	if err != nil {
		return protocol.AzureSecretResult{}, protocol.OperationReceipt{}, err
	}
	if result.Vault != nil {
		m.mu.Lock()
		session.VaultRefs[vaultRefKey(req.ApplicationObjectID, req.KeyID)] = *result.Vault
		m.mu.Unlock()
	}
	details := map[string]string{"key_id": req.KeyID, "vault_secret_name": result.Vault.SecretName, "vault_version": result.Vault.Version}
	receipt, err := m.receipt(ctx, protocol.EventSecretRead, session, req.ApplicationObjectID, details, now)
	return result, receipt, err
}

func (m *integrationManager) InvalidateSecret(ctx context.Context, sessionID, csrf string, req protocol.AzureSecretInvalidateRequest, now time.Time) (protocol.AzureCredential, protocol.OperationReceipt, error) {
	session, err := m.session(sessionID, csrf, now)
	if err != nil {
		return protocol.AzureCredential{}, protocol.OperationReceipt{}, err
	}
	if req.Version == "" {
		m.mu.Lock()
		if ref, ok := session.VaultRefs[vaultRefKey(req.ApplicationObjectID, req.KeyID)]; ok {
			req.Version = ref.Version
		}
		m.mu.Unlock()
	}
	credential, err := session.Client.InvalidateSecret(ctx, req)
	if err != nil {
		return credential, protocol.OperationReceipt{}, err
	}
	details := map[string]string{"key_id": req.KeyID, "vault_disabled": fmt.Sprint(credential.Vault != nil)}
	if credential.Vault != nil {
		details["vault_secret_name"] = credential.Vault.SecretName
		details["vault_version"] = credential.Vault.Version
	}
	m.mu.Lock()
	delete(session.VaultRefs, vaultRefKey(req.ApplicationObjectID, req.KeyID))
	m.mu.Unlock()
	receipt, err := m.receipt(ctx, protocol.EventSecretInvalidated, session, req.ApplicationObjectID, details, now)
	return credential, receipt, err
}

func validateIntegrationEvent(event protocol.AzureIntegrationEvent) error {
	for key, value := range event.Details {
		lowerKey := strings.ToLower(key)
		if strings.Contains(lowerKey, "secret_text") || strings.Contains(lowerKey, "client_secret") || strings.Contains(lowerKey, "password") || strings.Contains(lowerKey, "access_token") || lowerKey == "token" {
			return errors.New("integration event contains a forbidden secret-bearing detail")
		}
		lowerValue := strings.ToLower(value)
		if strings.Contains(lowerValue, "bearer ") {
			return errors.New("integration event contains a bearer token")
		}
	}
	return nil
}

func vaultRefKey(applicationObjectID, keyID string) string {
	return applicationObjectID + ":" + keyID
}

func (m *integrationManager) receipt(ctx context.Context, eventType protocol.EventType, session *IntegrationSession, applicationID string, details map[string]string, now time.Time) (protocol.OperationReceipt, error) {
	id, err := randomID("evt")
	if err != nil {
		return protocol.OperationReceipt{}, err
	}
	correlation, err := randomID("op")
	if err != nil {
		return protocol.OperationReceipt{}, err
	}
	event := protocol.AzureIntegrationEvent{ID: id, Type: string(eventType), CorrelationID: correlation, At: now.UTC(), Outcome: protocol.OutcomeSuccess, Provider: "azure-entra", ApplicationID: applicationID, Details: details}
	published := true
	if err := validateIntegrationEvent(event); err != nil {
		return protocol.OperationReceipt{}, err
	}
	if err := m.publisher.Publish(ctx, event); err != nil {
		published = false
		return protocol.OperationReceipt{ID: id, CorrelationID: correlation, EventPublished: false, Event: event}, fmt.Errorf("Azure operation succeeded but redacted event publication failed: %w", err)
	}
	return protocol.OperationReceipt{ID: id, CorrelationID: correlation, EventPublished: published, Event: event}, nil
}

func (m *integrationManager) allowConnection(key string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := now.Add(-time.Hour)
	attempts := m.connections[key]
	kept := attempts[:0]
	for _, attempt := range attempts {
		if attempt.After(cutoff) {
			kept = append(kept, attempt)
		}
	}
	if len(kept) >= m.maxConnections {
		m.connections[key] = kept
		return ErrIntegrationRateLimited
	}
	m.connections[key] = append(kept, now)
	return nil
}

func randomID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(raw[:]), nil
}

func redactIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 8 {
		return "********"
	}
	return value[:4] + "…" + value[len(value)-4:]
}

func secureEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var mismatch byte
	for i := range a {
		mismatch |= a[i] ^ b[i]
	}
	return mismatch == 0
}
