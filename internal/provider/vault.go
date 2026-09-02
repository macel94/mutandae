package provider

import (
	"context"
	"errors"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// ErrVaultUnsupported is returned when a provider adapter has no vault
// capability (a simulator, or a live adapter without a configured vault). The
// web layer maps it to a 409 conflict with an actionable message.
var ErrVaultUnsupported = errors.New("vault delivery is not configured for this provider adapter")

// CloudVault is the provider-neutral vault delivery capability of a
// CloudAdapter. It stores and retrieves credential material in the provider's
// native vault — Azure Key Vault for azure-entra, AWS Secrets Manager for
// aws-iam, and GCP Secret Manager for gcp-iam — so a provisioned or renewed
// secret has a durable, auditable home beyond the one-time HTTP response.
//
// Implementations must keep the trust boundary of the demo: secret values are
// write-only on Store and returned only from Read; references, names, and
// versions are safe to persist; errors must be redacted and must never embed
// the secret or the caller's credentials.
type CloudVault interface {
	// StoreSecret writes (a new version of) the identity's credential into the
	// vault and returns only the redacted reference.
	StoreSecret(ctx context.Context, identity protocol.MachineIdentity, keyID, secret string) (protocol.VaultReference, error)
	// ReadSecret retrieves the current (or pinned) version of the identity's
	// credential from the vault.
	ReadSecret(ctx context.Context, identity protocol.MachineIdentity, keyID, version string) (string, protocol.VaultReference, error)
	// RevokeSecret best-effort disables or schedules deletion of the vault
	// copy when the identity is retired.
	RevokeSecret(ctx context.Context, identity protocol.MachineIdentity, keyID string) (protocol.VaultReference, error)
}

// vaultFor returns the CloudVault capability of the adapter matching the
// identity's provider binding, mirroring the Rotate/Retire routing.
func (m *MultiProvider) vaultFor(identity protocol.MachineIdentity) (CloudVault, error) {
	kind := identity.Provider.Provider
	for _, a := range m.adapters {
		if a.Kind() != kind {
			continue
		}
		vault, ok := a.(CloudVault)
		if !ok {
			return nil, ErrVaultUnsupported
		}
		return vault, nil
	}
	return nil, ErrVaultUnsupported
}

// StoreSecret routes a vault write to the adapter named by the identity's
// provider binding.
func (m *MultiProvider) StoreSecret(ctx context.Context, identity protocol.MachineIdentity, keyID, secret string) (protocol.VaultReference, error) {
	vault, err := m.vaultFor(identity)
	if err != nil {
		return protocol.VaultReference{}, err
	}
	return vault.StoreSecret(ctx, identity, keyID, secret)
}

// ReadSecret routes a vault read to the adapter named by the identity's
// provider binding.
func (m *MultiProvider) ReadSecret(ctx context.Context, identity protocol.MachineIdentity, keyID, version string) (string, protocol.VaultReference, error) {
	vault, err := m.vaultFor(identity)
	if err != nil {
		return "", protocol.VaultReference{}, err
	}
	return vault.ReadSecret(ctx, identity, keyID, version)
}

// RevokeSecret routes a vault revocation to the adapter named by the
// identity's provider binding.
func (m *MultiProvider) RevokeSecret(ctx context.Context, identity protocol.MachineIdentity, keyID string) (protocol.VaultReference, error) {
	vault, err := m.vaultFor(identity)
	if err != nil {
		return protocol.VaultReference{}, err
	}
	return vault.RevokeSecret(ctx, identity, keyID)
}

// OneTimeSecretor exposes the most recent provider-issued secret (from Create
// or Rotate) so the control plane can deliver it to the vault. The value stays
// in adapter memory until consumed; adapters clear it on consumption.
type OneTimeSecretor interface {
	ConsumeOneTimeSecret(provider string) string
}

// ConsumeOneTimeSecret routes to the sub-adapter that issued the most recent
// secret for the named provider kind.
func (m *MultiProvider) ConsumeOneTimeSecret(provider string) string {
	for _, a := range m.adapters {
		if a.Kind() != provider {
			continue
		}
		issuer, ok := a.(interface{ ConsumeOneTimeSecret() string })
		if !ok {
			return ""
		}
		return issuer.ConsumeOneTimeSecret()
	}
	return ""
}
