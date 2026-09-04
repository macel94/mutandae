package protocol

import "errors"

// ErrVaultUnsupported is the canonical sentinel for "this adapter has no vault
// delivery capability". It is defined here — the shared, dependency-free
// contract package — so the control plane (consumer) and the provider adapters
// (implementations) test membership with errors.Is against one and the same
// value. Duplicating the sentinel per package would silently break that check.
//
// Adapters also return it (wrapped with context) when a configured native
// vault deterministically refuses the adapter's authorization, such as an
// AccessDenied from a governor principal that was never granted vault
// permissions: the capability does not exist in practice, so delivery skips
// silently and credential reads fall back to the cluster μVault copy.
var (
	ErrVaultUnsupported = errors.New("vault delivery is not configured for this provider adapter")
	// ErrForbidden means the requested provider identity is outside the
	// adapter's configured governance scope. It is safe to expose as the
	// protocol's 403-style forbidden error; callers must not retry it by
	// changing provider state.
	ErrForbidden = errors.New("protocol: operation is forbidden")
)
