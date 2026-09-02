// Package lifecycle is the control-plane domain layer. It holds the provider-
// neutral governance model for machine identities, the valid role of the
// μTandae Protocol state machine, and an in-memory store that orchestrates the
// lifecycle with a pluggable provider adapter.
//
// The store speaks protocol types end to end, so the backend genuinely works
// with the protocol contract. Provider-specific mechanics stay behind the
// Adapter interface; this package never depends on a concrete cloud SDK.
package lifecycle

import (
	"context"
	"errors"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// Sentinel errors returned by Store operations. They map onto protocol
// ErrorCodes for the wire and remain idiomatic for tests.
var (
	ErrAdapterRequired    = errors.New("provider adapter is required")
	ErrNotFound           = errors.New("identity not found")
	ErrInvalidTransition  = errors.New("invalid lifecycle transition")
	ErrAlreadyRetired     = errors.New("identity is retired")
	ErrRotationInProgress = errors.New("identity already has a rotation in progress")
	ErrProviderFailure    = errors.New("provider adapter failed")
	ErrConfirmationNeeded = errors.New("retirement requires explicit confirmation")
	ErrConformance        = protocol.ErrConformance
)

// Adapter is the provider-aware execution boundary the control plane consumes.
// Implementations translate protocol operations into provider mechanics and
// return protocol objects plus evidence. The public project ships one simulated
// azure-entra adapter; private production adapters implement the same boundary.
type Adapter interface {
	// Kind returns a stable provider identifier, e.g. "azure-entra".
	Kind() string
	// Discover returns the provider's current view of machine identities.
	Discover(ctx context.Context) ([]protocol.MachineIdentity, error)
	// Rotate performs a rotation of the identity's credential and returns the
	// provider-observed identity with new credential evidence.
	Rotate(ctx context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error)
	// Retire decommissions the identity in the provider and returns the
	// provider-observed (retired) identity.
	Retire(ctx context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error)
}

// Provisioner is the optional provisioning capability of an Adapter: it
// creates a brand-new, zero-permission identity in a real tenant. Simulators
// and non-provisioning adapters do not implement it, so the control plane falls
// back to a conflict for them.
type Provisioner interface {
	Create(ctx context.Context, provider, name string) (protocol.ProvisionResponse, error)
}

// VaultStore is the optional vault delivery capability of an Adapter: it
// stores, retrieves, and revokes credential material in the provider's native
// vault (Azure Key Vault, AWS Secrets Manager, GCP Secret Manager). The
// control plane consumes it so provision/renew/use/retire stay auditable
// lifecycle events regardless of which cloud the secret lands in.
type VaultStore interface {
	StoreSecret(ctx context.Context, identity protocol.MachineIdentity, keyID, secret string) (protocol.VaultReference, error)
	ReadSecret(ctx context.Context, identity protocol.MachineIdentity, keyID, version string) (string, protocol.VaultReference, error)
	RevokeSecret(ctx context.Context, identity protocol.MachineIdentity, keyID string) (protocol.VaultReference, error)
}

// OneTimeSecretor exposes the most recent provider-issued secret so the
// control plane can deliver a renewed credential to the vault.
type OneTimeSecretor interface {
	ConsumeOneTimeSecret(provider string) string
}

// ErrVaultUnsupported is returned when an operation needs a vault but the
// adapter has none configured.
var ErrVaultUnsupported = errors.New("vault delivery is not configured for this provider adapter")

// ErrorCode translates a lifecycle error to the closest protocol ErrorCode so
// handlers can emit a conformant failure envelope.
func ErrorCode(err error) protocol.ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrNotFound):
		return protocol.ErrCodeNotFound
	case errors.Is(err, ErrInvalidTransition):
		return protocol.ErrCodeInvalidTransition
	case errors.Is(err, ErrAlreadyRetired):
		return protocol.ErrCodeAlreadyRetired
	case errors.Is(err, ErrRotationInProgress):
		return protocol.ErrCodeRotationInProgress
	case errors.Is(err, ErrProviderFailure):
		return protocol.ErrCodeProviderFailure
	case errors.Is(err, ErrConfirmationNeeded):
		return protocol.ErrCodeConflict
	case errors.Is(err, ErrConformance):
		return protocol.ErrCodeConformanceFailure
	default:
		return protocol.ErrCodeInternal
	}
}

// NewError builds a protocol error with the correct code for an internal err.
func NewError(err error) protocol.Error {
	return protocol.NewError(ErrorCode(err), err.Error())
}
