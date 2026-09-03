package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// TestHashiCorpVaultRealServerDelivery exercises the KV v2 client against a
// real, running HashiCorp Vault — the cluster μVault of the hosted demo —
// and is skipped unless MUTANDAE_VAULT_TEST_ADDR and MUTANDAE_VAULT_TEST_TOKEN
// are set. All material lives under an isolated test prefix and is cleaned up,
// mirroring the Redis integration test discipline.
func TestHashiCorpVaultRealServerDelivery(t *testing.T) {
	addr := os.Getenv("MUTANDAE_VAULT_TEST_ADDR")
	token := os.Getenv("MUTANDAE_VAULT_TEST_TOKEN")
	if addr == "" || token == "" {
		t.Skip("MUTANDAE_VAULT_TEST_ADDR / MUTANDAE_VAULT_TEST_TOKEN are not set; run against the provisioned cluster μVault")
	}
	prefix := fmt.Sprintf("demo/test-%d", time.Now().UnixNano())
	store, err := NewHashiCorpVault(HashiCorpVaultConfig{
		Addr:   addr,
		Token:  token,
		Mount:  os.Getenv("MUTANDAE_VAULT_TEST_MOUNT"),
		Prefix: prefix,
	})
	if err != nil {
		t.Fatalf("configure vault store: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	identity := protocol.MachineIdentity{
		ID:          "mutandae-demo-vaultintegration",
		Name:        "mutandae-demo-vaultintegration",
		Environment: "integration",
		Provider:    protocol.ProviderBinding{Provider: "aws-iam", ProviderID: "mutandae-governor", AccountID: "572030963802"},
	}

	ref, err := store.StoreSecret(ctx, identity, "key-int-1", "integration-secret-value")
	if err != nil {
		t.Fatalf("store secret: %v", err)
	}
	if ref.SecretName == "" || ref.Version == "" {
		t.Fatalf("store returned an incomplete reference: %+v", ref)
	}
	if ref.Version != "1" {
		t.Fatalf("first version = %q, want 1", ref.Version)
	}

	value, readRef, err := store.ReadSecret(ctx, identity, "key-int-1", "")
	if err != nil {
		t.Fatalf("read secret: %v", err)
	}
	if value != "integration-secret-value" {
		t.Fatalf("read value = %q, want the stored secret", value)
	}
	if readRef.Version != ref.Version {
		t.Fatalf("read version = %q, want %q", readRef.Version, ref.Version)
	}

	// A rotation writes a new version under the same auditable path.
	rotated, err := store.StoreSecret(ctx, identity, "key-int-2", "rotated-secret-value")
	if err != nil {
		t.Fatalf("store rotated secret: %v", err)
	}
	if rotated.Version == ref.Version {
		t.Fatalf("rotated version %q must differ from %q", rotated.Version, ref.Version)
	}
	current, _, err := store.ReadSecret(ctx, identity, "key-int-2", "")
	if err != nil {
		t.Fatalf("read rotated secret: %v", err)
	}
	if current != "rotated-secret-value" {
		t.Fatalf("current value = %q, want the rotated secret", current)
	}

	// A pinned read still returns the exact historical version.
	pinnedValue, _, err := store.ReadSecret(ctx, identity, "key-int-1", ref.Version)
	if err != nil {
		t.Fatalf("read pinned secret: %v", err)
	}
	if pinnedValue != "integration-secret-value" {
		t.Fatalf("pinned value = %q, want the first version", pinnedValue)
	}

	// Revocation removes every version; a later read reports not found.
	if _, err := store.RevokeSecret(ctx, identity, "key-int-2"); err != nil {
		t.Fatalf("revoke secret: %v", err)
	}
	if _, _, err := store.ReadSecret(ctx, identity, "key-int-2", ""); err == nil {
		t.Fatal("read after revoke succeeded; want not found")
	} else if !errors.Is(err, ErrVaultSecretNotFound) {
		t.Fatalf("post-revoke error = %v, want ErrVaultSecretNotFound", err)
	}
}
