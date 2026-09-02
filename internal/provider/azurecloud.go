package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// azureKind ("azure-entra") is declared in azuresimulator.go and shared by the
// real adapter so both implementations produce identical ProviderBindings.

// AzureCloudAdapterConfig carries the connection material for a real Azure /
// Entra adapter. ClientSecret is write-only and never returned.
type AzureCloudAdapterConfig struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
	Now          func() time.Time
}

// AzureCloudAdapter is a real Microsoft Graph adapter behind the CloudAdapter
// boundary for the public demo. It identifies governed identities strictly by
// the mutandae-demo-* display-name namespace: it discovers, creates, rotates,
// and retires only applications whose display name carries that prefix. This is
// the safety boundary — the demo server's Application.ReadWrite.All credential
// could otherwise reach unrelated tenant applications, so every mutation is
// guarded by the namespace check in addition to the credential being
// least-privilege.
type AzureCloudAdapter struct {
	client   *AzureClient
	tenantID string
	now      func() time.Time
}

// NewAzureCloudAdapter validates connection material and returns a real Graph
// adapter. It does not contact Azure; the first Discover or Create verifies
// access with the configured client credentials.
func NewAzureCloudAdapter(cfg AzureCloudAdapterConfig) (*AzureCloudAdapter, error) {
	if strings.TrimSpace(cfg.TenantID) == "" {
		return nil, errors.New("azure: tenant_id is required")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, errors.New("azure: client_id is required")
	}
	if cfg.ClientSecret == "" {
		return nil, errors.New("azure: client_secret is required")
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	client, err := NewAzureClient(protocol.AzureIntegrationRequest{
		TenantID:     cfg.TenantID,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
	}, httpClient, now)
	if err != nil {
		return nil, err
	}
	return &AzureCloudAdapter{client: client, tenantID: cfg.TenantID, now: now}, nil
}

// Kind returns the stable provider identifier.
func (a *AzureCloudAdapter) Kind() string { return azureKind }

// Discover returns every demo-namespaced application that owns at least one
// credential.
func (a *AzureCloudAdapter) Discover(ctx context.Context) ([]protocol.MachineIdentity, error) {
	apps, err := a.client.ListApplicationsByPrefix(ctx, demoPrefix)
	if err != nil {
		return nil, err
	}
	identities := make([]protocol.MachineIdentity, 0, len(apps))
	for _, app := range apps {
		if !isDemoName(app.DisplayName) {
			continue
		}
		if len(app.Credentials) == 0 {
			continue // no live credential; not governed by Mutandae
		}
		identities = append(identities, a.toIdentity(app))
	}
	return identities, nil
}

// Create provisions a brand-new, zero-permission application registration
// (display name in the demo namespace) and one client secret, returning the
// secret exactly once. A newly created application has no API permissions and
// no admin consent, so it cannot do anything by itself.
func (a *AzureCloudAdapter) Create(ctx context.Context, hint string) (protocol.ProvisionResponse, error) {
	name, err := buildDemoName(hint, 8)
	if err != nil {
		return protocol.ProvisionResponse{}, err
	}
	if !isDemoName(name) {
		return protocol.ProvisionResponse{}, errors.New("azure: refusing to create an application outside the " + demoPrefix + "* namespace")
	}
	app, err := a.client.CreateApplication(ctx, protocol.AzureApplicationCreateRequest{DisplayName: name})
	if err != nil {
		return protocol.ProvisionResponse{}, err
	}
	secret, err := a.client.AddPassword(ctx, app.ObjectID, "demo-rotation", a.now().UTC().Add(90*24*time.Hour))
	if err != nil {
		_ = a.client.DeleteApplication(ctx, app.ObjectID)
		return protocol.ProvisionResponse{}, err
	}
	app.Credentials = []protocol.AzureCredential{secret.Credential}
	identity := a.toIdentity(app)
	return protocol.ProvisionResponse{
		APIVersion:    protocol.Version,
		Identity:      identity,
		OneTimeSecret: secret.SecretText,
		KeyID:         secret.Credential.KeyID,
		Instructions:  "This application registration has NO API permissions and NO admin consent, so its client credentials cannot do anything on their own. Store the secret now — it will never be shown again.",
	}, nil
}

// Rotate adds a new client secret and removes the rotated-out one for a demo
// application. Rotation never grants permissions.
func (a *AzureCloudAdapter) Rotate(ctx context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	if !isDemoName(identity.Name) {
		return protocol.MachineIdentity{}, errors.New("azure: refusing to rotate an application outside the " + demoPrefix + "* namespace")
	}
	objectID := identity.Provider.ProviderID
	currentKeyID := identity.Credential.KeyID
	secret, err := a.client.AddPassword(ctx, objectID, "demo-rotation-"+strings.ToLower(currentKeyID), a.now().UTC().Add(90*24*time.Hour))
	if err != nil {
		return protocol.MachineIdentity{}, err
	}
	if currentKeyID != "" && currentKeyID != secret.Credential.KeyID {
		if err := a.client.RemovePassword(ctx, objectID, currentKeyID); err != nil {
			return protocol.MachineIdentity{}, err
		}
	}
	app := protocol.AzureApplication{ObjectID: objectID, DisplayName: identity.Name, Credentials: []protocol.AzureCredential{secret.Credential}}
	return a.toIdentity(app), nil
}

// Retire decommissions a demo application by deleting it from the tenant. The
// control plane keeps a retired record in memory; the object is gone from
// Graph so it is no longer rediscovered.
func (a *AzureCloudAdapter) Retire(ctx context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	if !isDemoName(identity.Name) {
		return protocol.MachineIdentity{}, errors.New("azure: refusing to retire an application outside the " + demoPrefix + "* namespace")
	}
	objectID := identity.Provider.ProviderID
	if err := a.client.DeleteApplication(ctx, objectID); err != nil {
		return protocol.MachineIdentity{}, err
	}
	view := identity
	view.State = protocol.StateRetired
	view.Health = protocol.HealthAttention
	view.Credential = protocol.CredentialReference{
		Kind:     "client_secret",
		Location: "graph://applications/" + objectID,
		Delivery: "secret-manager",
	}
	return view, nil
}

func (a *AzureCloudAdapter) toIdentity(app protocol.AzureApplication) protocol.MachineIdentity {
	var keyID string
	var expiresAt time.Time
	for _, credential := range app.Credentials {
		if credential.ExpiresAt.After(expiresAt) {
			expiresAt = credential.ExpiresAt
			keyID = credential.KeyID
		}
	}
	if expiresAt.IsZero() {
		expiresAt = a.now().UTC().Add(90 * 24 * time.Hour)
	}
	health := protocol.HealthHealthy
	if !a.now().UTC().Before(expiresAt) {
		health = protocol.HealthAttention
	}
	return protocol.MachineIdentity{
		Name:        app.DisplayName,
		DisplayName: app.DisplayName,
		Environment: "demo",
		Provider: protocol.ProviderBinding{
			Provider:   azureKind,
			ProviderID: app.ObjectID,
			ObjectID:   app.ObjectID,
		},
		Ownership: protocol.Ownership{
			Team:        "Demo",
			Service:     app.DisplayName,
			Purpose:     "Public demo identity with zero permissions",
			Criticality: "low",
		},
		Policy: protocol.LifecyclePolicy{
			RenewalPeriod:    "P90D",
			ApprovalRequired: false,
		},
		Credential: protocol.CredentialReference{
			Kind:        "client_secret",
			Location:    "graph://applications/" + app.ObjectID,
			Fingerprint: azureFingerprint(app.ObjectID),
			KeyID:       keyID,
			Delivery:    "secret-manager",
		},
		State:     protocol.StateActive,
		Health:    health,
		ExpiresAt: expiresAt,
	}
}

func azureFingerprint(objectID string) string {
	sum := sha256.Sum256([]byte(objectID))
	return "sha256:" + hex.EncodeToString(sum[:])
}
