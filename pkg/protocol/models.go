package protocol

import "time"

// ProviderBinding identifies a machine identity inside a provider's domain.
// It is deliberately opaque to the control plane: providers decide what their
// identifier space looks like. A control plane only correlates on the identity
// "id" it assigns, never on provider internals.
type ProviderBinding struct {
	Provider   string `json:"provider"`    // e.g. "azure-entra", "aws-iam", "gcp-iam"
	ProviderID string `json:"provider_id"` // PKCE-agnostic, provider-side identifier
	TenantID   string `json:"tenant_id,omitempty"`
	ObjectID   string `json:"object_id,omitempty"`
	Region     string `json:"region,omitempty"`
	AccountID  string `json:"account_id,omitempty"`
	ProjectID  string `json:"project_id,omitempty"`
}

// Ownership is a first-class product object: who is accountable, which service,
// and for what purpose. Contacts are opaque display/slack/email handles.
type Ownership struct {
	Team        string   `json:"team"`
	Service     string   `json:"service"`
	Purpose     string   `json:"purpose"`
	Criticality string   `json:"criticality"` // e.g. low, medium, high, critical
	Contacts    []string `json:"contacts,omitempty"`
}

// LifecyclePolicy is the machine-readable renewal/governance policy.
// RenewalPeriod is expressed as an ISO-8601 duration string (e.g. "P90D").
type LifecyclePolicy struct {
	RenewalPeriod    string `json:"renewal_period"`
	GracePeriod      string `json:"grace_period,omitempty"`
	MaxAge           string `json:"max_age,omitempty"`
	ApprovalRequired bool   `json:"approval_required"`
}

// CredentialReference describes where related credential material lives and how
// to verify it, without making Mutandae a secret store. It SHOULD never carry
// secret material.
type CredentialReference struct {
	Kind        string `json:"kind"`     // e.g. "client_secret", "x509_thumbprint", "access_key"
	Location    string `json:"location"` // provider reference, not a secret
	Fingerprint string `json:"fingerprint,omitempty"`
	KeyID       string `json:"key_id,omitempty"`
	Delivery    string `json:"delivery,omitempty"` // e.g. "keyvault-ref", "environment", "secret-manager"
}

// Metadata reserves an extension point for provider- or deployment-specific
// key/value notes without breaking version conformance.
type Metadata map[string]string

// AzureIntegrationRequest is accepted only by the interactive integration
// endpoint. ClientSecret is write-only: it must never be copied into a
// response, event, snapshot, log, or HTML template.
type AzureIntegrationRequest struct {
	TenantID     string              `json:"tenant_id"`
	ClientID     string              `json:"client_id"`
	ClientSecret string              `json:"client_secret"`
	Vault        *VaultConfiguration `json:"vault,omitempty"`
	RequestedBy  string              `json:"requested_by,omitempty"`
}

// VaultConfiguration describes an existing Azure Key Vault that may receive
// newly-created credentials. Mutandae does not create vaults or role
// assignments; the supplied client must already have the required data-plane
// permissions.
type VaultConfiguration struct {
	URL            string   `json:"url"`
	SecretPrefix   string   `json:"secret_prefix,omitempty"`
	OwnerObjectIDs []string `json:"owner_object_ids,omitempty"`
}

// VaultReference is safe to persist and return. It identifies a vault secret
// version but never contains the secret value.
type VaultReference struct {
	URL            string    `json:"url"`
	SecretName     string    `json:"secret_name"`
	Version        string    `json:"version,omitempty"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
	OwnerObjectIDs []string  `json:"owner_object_ids,omitempty"`
}

// AzureIntegrationSession is the redacted view of an in-memory interactive
// session. Tenant and client IDs are intentionally shortened in responses.
type AzureIntegrationSession struct {
	ID              string    `json:"id"`
	Provider        string    `json:"provider"`
	TenantHint      string    `json:"tenant_hint"`
	ClientHint      string    `json:"client_hint"`
	ExpiresAt       time.Time `json:"expires_at"`
	VaultConfigured bool      `json:"vault_configured"`
	Capabilities    []string  `json:"capabilities"`
}

// AzureIntegrationRequirements describes the least-privilege contract shown
// before a user submits credentials.
type AzureIntegrationRequirements struct {
	GraphApplicationPermission string   `json:"graph_application_permission"`
	GraphOperations            []string `json:"graph_operations"`
	VaultOptional              bool     `json:"vault_optional"`
	VaultWriteRole             string   `json:"vault_write_role,omitempty"`
	VaultReadRole              string   `json:"vault_read_role,omitempty"`
	OwnerEnforcement           string   `json:"owner_enforcement"`
	Warnings                   []string `json:"warnings"`
}

// AzureIntegrationEvent is a redacted operation event. It is suitable for
// Redis pub/sub and an optional short-lived Redis event receipt; it must never
// contain ClientSecret, access tokens, or SecretText.
type AzureIntegrationEvent struct {
	ID            string            `json:"id"`
	Type          string            `json:"type"`
	CorrelationID string            `json:"correlation_id"`
	At            time.Time         `json:"at"`
	Outcome       Outcome           `json:"outcome"`
	Provider      string            `json:"provider"`
	ApplicationID string            `json:"application_id,omitempty"`
	Details       map[string]string `json:"details,omitempty"`
}

// OperationReceipt proves that the control-plane operation emitted a redacted
// event. It does not prove a distributed transaction with Azure; provider
// changes and Redis publication are separate systems.
type OperationReceipt struct {
	ID             string                `json:"id"`
	CorrelationID  string                `json:"correlation_id"`
	EventPublished bool                  `json:"event_published"`
	Event          AzureIntegrationEvent `json:"event"`
}

// AzureApplication is a safe subset of an Entra application registration.
type AzureApplication struct {
	ObjectID             string            `json:"object_id"`
	ApplicationID        string            `json:"application_id"`
	DisplayName          string            `json:"display_name"`
	CreatedAt            time.Time         `json:"created_at,omitempty"`
	OwnedByCallingClient bool              `json:"owned_by_calling_client"`
	Credentials          []AzureCredential `json:"credentials,omitempty"`
}

// AzureCredential contains Graph metadata only. SecretText is never included
// here because Microsoft Graph does not return it after creation.
type AzureCredential struct {
	KeyID       string          `json:"key_id"`
	DisplayName string          `json:"display_name,omitempty"`
	StartAt     time.Time       `json:"start_at,omitempty"`
	ExpiresAt   time.Time       `json:"expires_at,omitempty"`
	Hint        string          `json:"hint,omitempty"`
	Vault       *VaultReference `json:"vault,omitempty"`
}

// AzureSecretResult is returned by a create operation. SecretText is
// intentionally one-time: callers must copy it or enable vault storage first.
type AzureSecretResult struct {
	Credential AzureCredential `json:"credential"`
	SecretText string          `json:"secret_text,omitempty"`
	OneTime    bool            `json:"one_time"`
	Vault      *VaultReference `json:"vault,omitempty"`
}

// MachineIdentity is the controlled, versioned representation of a governed
// non-human identity as it crosses cloud adapter ↔ control plane ↔ frontend.
type MachineIdentity struct {
	ID            string              `json:"id"`
	Name          string              `json:"name"`
	DisplayName   string              `json:"display_name,omitempty"`
	Namespace     string              `json:"namespace,omitempty"`
	Environment   string              `json:"environment,omitempty"`
	Provider      ProviderBinding     `json:"provider,omitempty"`
	Ownership     Ownership           `json:"ownership,omitempty"`
	Policy        LifecyclePolicy     `json:"policy,omitempty"`
	Credential    CredentialReference `json:"credential,omitempty"`
	State         State               `json:"state"`
	Health        Health              `json:"health"`
	ExpiresAt     time.Time           `json:"expires_at"`
	LastRotatedAt time.Time           `json:"last_rotated_at,omitempty"`
	CreatedAt     time.Time           `json:"created_at,omitempty"`
	UpdatedAt     time.Time           `json:"updated_at,omitempty"`
	Metadata      Metadata            `json:"metadata,omitempty"`
}

// LifecycleEvent is an immutable audit-correlation record. It uses the dotted
// EventType taxonomy and an Outcome.
type LifecycleEvent struct {
	ID            string            `json:"id"`
	IdentityID    string            `json:"identity_id"`
	Type          EventType         `json:"type"`
	Summary       string            `json:"summary"`
	Actor         string            `json:"actor"`
	Outcome       Outcome           `json:"outcome"`
	At            time.Time         `json:"at"`
	CorrelationID string            `json:"correlation_id,omitempty"`
	RunID         string            `json:"run_id,omitempty"`
	Details       map[string]string `json:"details,omitempty"`
}

// RotationRun records a planned or executed renewal/rotation workflow. A
// control plane tracks it from requested → started → terminal, attaching
// provider evidence when it becomes available.
type RotationRun struct {
	ID          string              `json:"id"`
	IdentityID  string              `json:"identity_id"`
	Status      RotationStatus      `json:"status"`
	RequestedBy string              `json:"requested_by,omitempty"`
	RequestedAt time.Time           `json:"requested_at,omitempty"`
	StartedAt   time.Time           `json:"started_at,omitempty"`
	FinishedAt  time.Time           `json:"finished_at,omitempty"`
	Outcome     Outcome             `json:"outcome,omitempty"`
	Evidence    CredentialReference `json:"evidence,omitempty"`
	Error       string              `json:"error,omitempty"`
}
