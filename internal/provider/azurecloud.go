package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
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
	// Scope restricts which application display names this adapter may govern.
	// Patterns use path.Match's fnmatch-style syntax, not regular expressions.
	Scope Scope
	// VaultURL, when set, enables the vault delivery capability against an
	// existing Azure Key Vault (must be an HTTPS *.vault.azure.net endpoint).
	// The governor application needs the Key Vault data-plane role documented
	// in docs/live-demo.md; Graph permissions do not grant vault access.
	VaultURL string
	// VaultSecretPrefix restricts the Key Vault secret-name namespace the demo
	// writes to (default "mutandae").
	VaultSecretPrefix string
}

// AzureCloudAdapter is a real Microsoft Graph adapter behind the CloudAdapter
// boundary for the public demo. It identifies governed applications through
// its configured Scope: it discovers, creates, rotates, and retires only
// display names matched by that allow-list and not excluded by its deny-list.
// This is the safety boundary — the demo server's Application.ReadWrite.All
// credential could otherwise reach unrelated tenant applications, so every
// mutation is guarded by the scope in addition to the credential being
// least-privilege.
type AzureCloudAdapter struct {
	client   *AzureClient
	tenantID string
	now      func() time.Time
	scope    Scope
	vault    *azureDemoVault

	mu            sync.Mutex
	oneTimeSecret string
	oneTimeKeyID  string
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
	scope, err := validateRealScope(cfg.Scope, false)
	if err != nil {
		return nil, fmt.Errorf("azure: %w", err)
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
	adapter := &AzureCloudAdapter{client: client, tenantID: cfg.TenantID, now: now, scope: scope}
	if strings.TrimSpace(cfg.VaultURL) != "" {
		vault, err := newAzureDemoVault(cfg.VaultURL, cfg.VaultSecretPrefix, scope, client, httpClient, now)
		if err != nil {
			return nil, err
		}
		adapter.vault = vault
	}
	return adapter, nil
}

// Kind returns the stable provider identifier.
func (a *AzureCloudAdapter) Kind() string { return azureKind }

// Scope returns the active non-secret governance scope.
func (a *AzureCloudAdapter) Scope() Scope { return a.scope }

// Discover returns every in-scope application that owns at least one
// credential. Filtering happens before an application is exposed to the
// control plane, regardless of whether the scope is a prefix or a pattern.
func (a *AzureCloudAdapter) Discover(ctx context.Context) ([]protocol.MachineIdentity, error) {
	apps, err := a.client.ListApplications(ctx)
	if err != nil {
		return nil, err
	}
	identities := make([]protocol.MachineIdentity, 0, len(apps))
	for _, app := range apps {
		if !a.scope.Match(app.DisplayName) {
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
	name, err := buildScopedName(a.scope, hint, 8)
	if err != nil {
		return protocol.ProvisionResponse{}, err
	}
	if !a.scope.Match(name) {
		return protocol.ProvisionResponse{}, forbiddenScopeError(azureKind, name, a.scope)
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
	a.rememberOneTimeSecret(secret.SecretText, secret.Credential.KeyID)
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
	if strings.TrimSpace(identity.Name) == "" || !a.scope.Match(identity.Name) {
		return protocol.MachineIdentity{}, forbiddenScopeError(azureKind, identity.Name, a.scope)
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
	a.rememberOneTimeSecret(secret.SecretText, secret.Credential.KeyID)
	app := protocol.AzureApplication{ObjectID: objectID, DisplayName: identity.Name, Credentials: []protocol.AzureCredential{secret.Credential}}
	return a.toIdentity(app), nil
}

// PlanRotate mirrors Graph mutations performed by Rotate without contacting
// Graph or changing adapter state.
func (a *AzureCloudAdapter) PlanRotate(ctx context.Context, id string) ([]protocol.PlannedOperation, error) {
	_ = ctx
	name := strings.TrimSpace(id)
	if name == "" {
		return nil, fmt.Errorf("%s: plan rotate requires an identity id", azureKind)
	}
	if !a.scope.Match(name) {
		return nil, forbiddenScopeError(azureKind, name, a.scope)
	}
	return []protocol.PlannedOperation{
		planned("graph.addPassword", name, "Add a replacement Microsoft Graph password credential.", true, false),
		planned("graph.removePassword", name, "Remove the rotated-out Graph password credential.", false, true),
	}, nil
}

// PlanRetire mirrors the Graph application deletion performed by Retire.
func (a *AzureCloudAdapter) PlanRetire(ctx context.Context, id string) ([]protocol.PlannedOperation, error) {
	_ = ctx
	name := strings.TrimSpace(id)
	if name == "" {
		return nil, fmt.Errorf("%s: plan retire requires an identity id", azureKind)
	}
	if !a.scope.Match(name) {
		return nil, forbiddenScopeError(azureKind, name, a.scope)
	}
	return []protocol.PlannedOperation{
		planned("graph.deleteApplication", name, "Delete the application registration so its credentials can no longer authenticate.", false, true),
	}, nil
}

func (a *AzureCloudAdapter) PlanRotateIdentity(ctx context.Context, identity protocol.MachineIdentity) ([]protocol.PlannedOperation, error) {
	name := identity.Name
	if strings.TrimSpace(name) == "" {
		name = identity.Provider.ProviderID
	}
	return a.PlanRotate(ctx, name)
}

func (a *AzureCloudAdapter) PlanRetireIdentity(ctx context.Context, identity protocol.MachineIdentity) ([]protocol.PlannedOperation, error) {
	name := identity.Name
	if strings.TrimSpace(name) == "" {
		name = identity.Provider.ProviderID
	}
	return a.PlanRetire(ctx, name)
}

// rememberOneTimeSecret buffers the freshly issued secret in process memory so
// the control plane can deliver it to the configured Key Vault. It is cleared
// on consumption and never placed into a protocol object, event, snapshot, or
// log.
func (a *AzureCloudAdapter) rememberOneTimeSecret(value, keyID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.oneTimeSecret = value
	a.oneTimeKeyID = keyID
}

// ConsumeOneTimeSecret returns and clears the most recent one-time secret
// created by Create or Rotate. The second call returns "".
func (a *AzureCloudAdapter) ConsumeOneTimeSecret() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	value := a.oneTimeSecret
	a.oneTimeSecret = ""
	return value
}

// Retire decommissions a demo application by deleting it from the tenant. The
// control plane keeps a retired record in memory; the object is gone from
// Graph so it is no longer rediscovered.
func (a *AzureCloudAdapter) Retire(ctx context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	if strings.TrimSpace(identity.Name) == "" || !a.scope.Match(identity.Name) {
		return protocol.MachineIdentity{}, forbiddenScopeError(azureKind, identity.Name, a.scope)
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
			// The tenant scope is part of the public, non-secret identity
			// binding: tenant ids ride in tokens and ARNs, and the audit
			// trail names which tenant an identity lives in.
			TenantID: a.tenantID,
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

// --- CloudVault capability (Azure Key Vault delivery) ---

// StoreSecret writes the identity's credential into the configured Key Vault
// as a new secret version. It is refused when no vault is configured or the
// identity sits outside the demo namespace.
func (a *AzureCloudAdapter) StoreSecret(ctx context.Context, identity protocol.MachineIdentity, keyID, secret string) (protocol.VaultReference, error) {
	if strings.TrimSpace(identity.Name) == "" || !a.scope.Match(identity.Name) {
		return protocol.VaultReference{}, forbiddenScopeError(azureKind, identity.Name, a.scope)
	}
	if a.vault == nil {
		return protocol.VaultReference{}, ErrVaultUnsupported
	}
	return a.vault.StoreSecret(ctx, identity, keyID, secret)
}

// ReadSecret retrieves the current (or pinned) version of the identity's
// credential from the configured Key Vault.
func (a *AzureCloudAdapter) ReadSecret(ctx context.Context, identity protocol.MachineIdentity, keyID, version string) (string, protocol.VaultReference, error) {
	if strings.TrimSpace(identity.Name) == "" || !a.scope.Match(identity.Name) {
		return "", protocol.VaultReference{}, forbiddenScopeError(azureKind, identity.Name, a.scope)
	}
	if a.vault == nil {
		return "", protocol.VaultReference{}, ErrVaultUnsupported
	}
	return a.vault.ReadSecret(ctx, identity, keyID, version)
}

// RevokeSecret disables the current version of the identity's vault secret.
func (a *AzureCloudAdapter) RevokeSecret(ctx context.Context, identity protocol.MachineIdentity, keyID string) (protocol.VaultReference, error) {
	if strings.TrimSpace(identity.Name) == "" || !a.scope.Match(identity.Name) {
		return protocol.VaultReference{}, forbiddenScopeError(azureKind, identity.Name, a.scope)
	}
	if a.vault == nil {
		return protocol.VaultReference{}, ErrVaultUnsupported
	}
	return a.vault.RevokeSecret(ctx, identity, keyID)
}
