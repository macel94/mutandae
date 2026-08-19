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
