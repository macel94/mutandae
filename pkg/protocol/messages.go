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
	Provider    ProviderBinding     `json:"provider"`
	Ownership   Ownership           `json:"ownership"`
	Policy      LifecyclePolicy     `json:"policy"`
	Credential  CredentialReference `json:"credential,omitempty"`
	ExpiresAt   time.Time           `json:"expires_at,omitempty"`
	RequestedBy string              `json:"requested_by,omitempty"`
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
