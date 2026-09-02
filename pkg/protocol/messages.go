package protocol

import "time"

// Envelopes are the request/response documents exchanged on the control-plane
// API and between the control plane and provider adapters. Every envelope
// carries api_version so a consumer can detect and reject version skew.

// ListRequest filters the identity inventory. All filters are optional.
type ListRequest struct {
	Provider    string   `json:"provider,omitempty"`
	Environment string   `json:"environment,omitempty"`
	State       State    `json:"state,omitempty"`
	Limit       int      `json:"limit,omitempty"`
	After       string   `json:"after,omitempty"`
	Namespaces  []string `json:"namespaces,omitempty"`
}

// ListResponse returns a conformant inventory.
type ListResponse struct {
	APIVersion string            `json:"api_version"`
	Total      int               `json:"total"`
	Identities []MachineIdentity `json:"identities"`
	Omitted    int               `json:"omitted,omitempty"` // >0 when the list was truncated
	Error      *Error            `json:"error,omitempty"`
}

// InspectRequest fetches a single identity by control-plane ID.
type InspectRequest struct {
	ID string `json:"id"`
}

// InspectResponse returns a single conformant identity.
type InspectResponse struct {
	APIVersion string          `json:"api_version"`
	Identity   MachineIdentity `json:"identity"`
	Error      *Error          `json:"error,omitempty"`
}

// RegisterRequest provisions or imports a new machine identity. Provider
// binding is required; the control plane assigns "id" unless one is supplied.
type RegisterRequest struct {
	ID          string              `json:"id,omitempty"`
	Name        string              `json:"name"`
	DisplayName string              `json:"display_name,omitempty"`
	Namespace   string              `json:"namespace,omitempty"`
	Environment string              `json:"environment,omitempty"`
	Provider    ProviderBinding     `json:"provider"`
	Ownership   Ownership           `json:"ownership"`
	Policy      LifecyclePolicy     `json:"policy"`
	Credential  CredentialReference `json:"credential,omitempty"`
	ExpiresAt   time.Time           `json:"expires_at,omitempty"`
	RequestedBy string              `json:"requested_by,omitempty"`
}

// RequestedByOrDefault returns the actor that requested registration, defaulting
// to the control plane actor when none is supplied.
func (r RegisterRequest) RequestedByOrDefault() string {
	if r.RequestedBy != "" {
		return r.RequestedBy
	}
	return ActorControlPlane
}

// RegisterResponse returns the stored identity plus the audit events produced
// by registration.
type RegisterResponse struct {
	APIVersion string           `json:"api_version"`
	Identity   MachineIdentity  `json:"identity"`
	Events     []LifecycleEvent `json:"events,omitempty"`
	Error      *Error           `json:"error,omitempty"`
}

// RotateRequest starts a renewal/rotation for a machine identity.
type RotateRequest struct {
	ID          string   `json:"id"`
	RequestedBy string   `json:"requested_by,omitempty"`
	Reason      string   `json:"reason,omitempty"`
	Metadata    Metadata `json:"metadata,omitempty"`
}

// RotateResponse returns the post-rotation identity, the run, and its events.
type RotateResponse struct {
	APIVersion string           `json:"api_version"`
	Identity   MachineIdentity  `json:"identity"`
	Rotation   RotationRun      `json:"rotation"`
	Events     []LifecycleEvent `json:"events,omitempty"`
	Error      *Error           `json:"error,omitempty"`
}

// RequestedByOrDefault returns the actor that requested the rotation, defaulting
// to the operator actor when none is supplied.
func (r RotateRequest) RequestedByOrDefault() string {
	if r.RequestedBy != "" {
		return r.RequestedBy
	}
	return ActorOperator
}

// RetireRequest decommissions a machine identity through an explicit lifecycle
// transition.
type RetireRequest struct {
	ID          string `json:"id"`
	RequestedBy string `json:"requested_by,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Confirm     bool   `json:"confirm"`
}

// RetireResponse returns the post-retirement identity plus its events.
type RetireResponse struct {
	APIVersion string           `json:"api_version"`
	Identity   MachineIdentity  `json:"identity"`
	Events     []LifecycleEvent `json:"events,omitempty"`
	Error      *Error           `json:"error,omitempty"`
}

// RequestedByOrDefault returns the actor that requested retirement, defaulting
// to the operator actor when none is supplied.
func (r RetireRequest) RequestedByOrDefault() string {
	if r.RequestedBy != "" {
		return r.RequestedBy
	}
	return ActorOperator
}

// ProvisionRequest asks the control plane to provision a brand-new machine
// identity in a real tenant for the public demo. The created identity is always
// zero-permission (no policy, role, group, or granted API permission) and is
// never given a login path. Provider selects the target cloud adapter.
// RequestedBy and OwnerIP are set by the web layer; OwnerIP never leaves the
// server and is never logged or persisted.
type ProvisionRequest struct {
	Provider    string `json:"provider"`
	Purpose     string `json:"purpose,omitempty"`
	RequestedBy string `json:"requested_by,omitempty"`
	OwnerIP     string `json:"-"`
}

// ProvisionResponse returns the provisioned identity plus a one-time secret
// that is written only to this single HTTP response. The control plane never
// persists OneTimeSecret, and any audit trail carries only KeyID/Location.
type ProvisionResponse struct {
	APIVersion    string          `json:"api_version"`
	Identity      MachineIdentity `json:"identity"`
	OneTimeSecret string          `json:"one_time_secret,omitempty"`
	KeyID         string          `json:"key_id,omitempty"`
	Instructions  string          `json:"instructions,omitempty"`
	// Vault, when set, is the redacted reference of the vault secret that
	// received the credential. It identifies the secret name and version in the
	// selected provider-native vault; it never contains secret material.
	Vault *VaultReference `json:"vault,omitempty"`
	Error *Error          `json:"error,omitempty"`
}

// UseRequest asks the control plane to retrieve the current credential of one
// governed identity from the selected provider-native vault. Every successful
// use is audited as credential.used; the secret value is written only to the
// single HTTP response and never persisted.
type UseRequest struct {
	ID          string `json:"id"`
	RequestedBy string `json:"requested_by,omitempty"`
	// Version optionally pins a specific vault secret version; empty means the
	// current version.
	Version string `json:"version,omitempty"`
}

// UseResponse returns the vault-retrieved credential once. Secret material is
// never persisted by the control plane; audit trails record the vault
// reference (name, version, key id) only.
type UseResponse struct {
	APIVersion string          `json:"api_version"`
	Identity   MachineIdentity `json:"identity"`
	KeyID      string          `json:"key_id,omitempty"`
	Secret     string          `json:"secret,omitempty"`
	Vault      *VaultReference `json:"vault,omitempty"`
	Error      *Error          `json:"error,omitempty"`
}

// RequestedByOrDefault returns the actor that requested the use, defaulting to
// the operator actor when none is supplied.
func (r UseRequest) RequestedByOrDefault() string {
	if r.RequestedBy != "" {
		return r.RequestedBy
	}
	return ActorOperator
}

// RequestedByOrDefault returns the actor that requested provisioning, defaulting
// to the control plane actor when none is supplied.
func (r ProvisionRequest) RequestedByOrDefault() string {
	if r.RequestedBy != "" {
		return r.RequestedBy
	}
	return ActorControlPlane
}

// Configuration is the safe, read-only runtime description exposed to demo
// users. It deliberately excludes connection strings, credentials, provider
// endpoints, and tenant identifiers.
type Configuration struct {
	Service         string    `json:"service"`
	ProtocolVersion string    `json:"protocol_version"`
	MediaType       string    `json:"media_type"`
	Environment     string    `json:"environment"`
	Provider        string    `json:"provider"`
	Persistence     string    `json:"persistence"`
	ReadOnly        bool      `json:"read_only"`
	Features        []string  `json:"features"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// ConfigurationResponse is the versioned envelope for the safe configuration
// view consumed by the frontend and evaluators.
type ConfigurationResponse struct {
	APIVersion    string        `json:"api_version"`
	Configuration Configuration `json:"configuration"`
	Error         *Error        `json:"error,omitempty"`
}

// AzureIntegrationRequirementsResponse advertises the real-tenant permission
// and vault prerequisites without revealing deployment secrets.
type AzureIntegrationRequirementsResponse struct {
	APIVersion   string                       `json:"api_version"`
	Requirements AzureIntegrationRequirements `json:"requirements"`
	Error        *Error                       `json:"error,omitempty"`
}

// AzureIntegrationResponse returns only redacted session metadata.
type AzureIntegrationResponse struct {
	APIVersion string                  `json:"api_version"`
	Session    AzureIntegrationSession `json:"session"`
	CSRFToken  string                  `json:"csrf_token,omitempty"`
	Error      *Error                  `json:"error,omitempty"`
}

// AzureApplicationsResponse lists safe application metadata.
type AzureApplicationsResponse struct {
	APIVersion   string             `json:"api_version"`
	Applications []AzureApplication `json:"applications"`
	Receipt      *OperationReceipt  `json:"receipt,omitempty"`
	Error        *Error             `json:"error,omitempty"`
}

// AzureApplicationResponse returns one application and a redacted operation
// receipt.
type AzureApplicationResponse struct {
	APIVersion  string            `json:"api_version"`
	Application AzureApplication  `json:"application"`
	Receipt     *OperationReceipt `json:"receipt,omitempty"`
	Error       *Error            `json:"error,omitempty"`
}

// AzureApplicationCreateRequest creates a new application owned by the
// supplied calling client under Graph's Application.ReadWrite.OwnedBy model.
type AzureApplicationCreateRequest struct {
	DisplayName string `json:"display_name"`
}

// AzureSecretCreateRequest asks Graph to generate a new client secret for an
// application. SecretText is returned only in this operation's response.
type AzureSecretCreateRequest struct {
	ApplicationObjectID string    `json:"application_object_id"`
	DisplayName         string    `json:"display_name"`
	ExpiresAt           time.Time `json:"expires_at,omitempty"`
	StoreInVault        bool      `json:"store_in_vault"`
}

// AzureSecretResponse returns one-time secret material only from an explicit
// secret-creation operation.
type AzureSecretResponse struct {
	APIVersion string            `json:"api_version"`
	Secret     AzureSecretResult `json:"secret"`
	Receipt    OperationReceipt  `json:"receipt"`
	Error      *Error            `json:"error,omitempty"`
}

// AzureSecretReadRequest retrieves a previously stored version from the
// configured Key Vault. It never reads plaintext from Redis or Graph.
type AzureSecretReadRequest struct {
	ApplicationObjectID string `json:"application_object_id"`
	KeyID               string `json:"key_id"`
	Version             string `json:"version,omitempty"`
}

// AzureSecretInvalidateRequest revokes a Graph password credential. If a vault
// reference is supplied, the vault version is disabled/deleted only when the
// configured vault client has the corresponding permission.
type AzureSecretInvalidateRequest struct {
	ApplicationObjectID string `json:"application_object_id"`
	KeyID               string `json:"key_id"`
	Version             string `json:"version,omitempty"`
}

// AzureSecretReadResponse returns the one-time vault value to the authorized
// interactive session and a redacted receipt.
type AzureSecretReadResponse struct {
	APIVersion string            `json:"api_version"`
	Secret     AzureSecretResult `json:"secret"`
	Receipt    OperationReceipt  `json:"receipt"`
	Error      *Error            `json:"error,omitempty"`
}

// AzureSecretInvalidateResponse returns no secret material.
type AzureSecretInvalidateResponse struct {
	APIVersion string           `json:"api_version"`
	Credential AzureCredential  `json:"credential"`
	Receipt    OperationReceipt `json:"receipt"`
	Error      *Error           `json:"error,omitempty"`
}

// ErrorResponse is the canonical failure document.
type ErrorResponse struct {
	APIVersion string `json:"api_version"`
	Error      Error  `json:"error"`
}

// DiscoveryResource advertises a single related protocol resource.
type DiscoveryResource struct {
	Rel      string `json:"rel"` // relation: identity, list, register, inspect, rotate, retire
	Method   string `json:"method"`
	HREF     string `json:"href"`
	Envelope string `json:"envelope,omitempty"`
}

// DiscoveryIndex is returned by the protocol root, advertising the versioned
// resources a consumer may use.
type DiscoveryIndex struct {
	APIVersion string              `json:"api_version"`
	Service    string              `json:"service"`
	MediaType  string              `json:"media_type"`
	Resources  []DiscoveryResource `json:"resources"`
	Error      *Error              `json:"error,omitempty"`
}

// Failure is a small helper to build an ErrorResponse.
func Failure(e Error) ErrorResponse {
	return ErrorResponse{APIVersion: Version, Error: e}
}

// NewError builds an Error value.
func NewError(code ErrorCode, message string) Error {
	return Error{Code: code, Message: message}
}
