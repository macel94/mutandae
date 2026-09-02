package lifecycle

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// vaultAdapter wraps the provisioning fake with the VaultStore and
// OneTimeSecretor capabilities so the store's delivery orchestration can be
// exercised end to end without a cloud.
type vaultAdapter struct {
	*provisioningAdapter
	failStore  error
	failRead   error
	failRevoke error

	mu      sync.Mutex
	stored  map[string]string // secretName -> secret value
	revoked []string
	issued  string // one-time secret a rotation would hand to the control plane
}

func (v *vaultAdapter) StoreSecret(_ context.Context, identity protocol.MachineIdentity, keyID, secret string) (protocol.VaultReference, error) {
	if v.failStore != nil {
		return protocol.VaultReference{}, v.failStore
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.stored == nil {
		v.stored = map[string]string{}
	}
	v.stored[identity.Name+"|"+keyID] = secret
	return protocol.VaultReference{URL: "vault://test", SecretName: identity.Name, Version: "v1", ExpiresAt: now().Add(24 * time.Hour)}, nil
}

func (v *vaultAdapter) ReadSecret(_ context.Context, identity protocol.MachineIdentity, _, _ string) (string, protocol.VaultReference, error) {
	if v.failRead != nil {
		return "", protocol.VaultReference{}, v.failRead
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	value, ok := v.stored[identity.Name+"|"+identity.Credential.KeyID]
	if !ok {
		return "", protocol.VaultReference{}, fmt.Errorf("no secret stored for %s", identity.Name)
	}
	return value, protocol.VaultReference{URL: "vault://test", SecretName: identity.Name, Version: "v1"}, nil
}

func (v *vaultAdapter) RevokeSecret(_ context.Context, identity protocol.MachineIdentity, _ string) (protocol.VaultReference, error) {
	if v.failRevoke != nil {
		return protocol.VaultReference{}, v.failRevoke
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.revoked = append(v.revoked, identity.Name)
	return protocol.VaultReference{URL: "vault://test", SecretName: identity.Name, Version: "v1"}, nil
}

func (v *vaultAdapter) ConsumeOneTimeSecret(provider string) string {
	if provider != "aws-iam" {
		return ""
	}
	issued := v.issued
	v.issued = ""
	return issued
}

func vaultTestStore(t *testing.T, adapter Adapter) *Store {
	t.Helper()
	return testStore(t, adapter)
}

func TestProvisionDeliversSecretToVaultAndAuditsIt(t *testing.T) {
	adapter := &vaultAdapter{provisioningAdapter: &provisioningAdapter{fakeAdapter: &fakeAdapter{}}}
	store := vaultTestStore(t, adapter)

	resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam", Purpose: "demo"}, now())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if resp.Vault == nil {
		t.Fatal("provision response carried no vault reference")
	}
	if resp.Vault.SecretName != "mutandae-demo-ab12" || resp.Vault.Version == "" {
		t.Fatalf("unexpected vault reference: %+v", resp.Vault)
	}
	// The vault actually received the secret value.
	if got := adapter.stored["mutandae-demo-ab12|key-1"]; got != "top-secret" {
		t.Fatalf("vault stored value = %q, want the issued secret", got)
	}
	// The audit trail records the delivery with references only.
	events, _ := store.Events(resp.Identity.ID)
	var delivered *protocol.LifecycleEvent
	for i := range events {
		if events[i].Type == protocol.EventCredentialDelivered {
			delivered = &events[i]
			break
		}
	}
	if delivered == nil {
		t.Fatal("no credential.delivered event recorded")
	}
	if delivered.Outcome != protocol.OutcomeSuccess {
		t.Fatalf("delivered outcome = %q", delivered.Outcome)
	}
	if strings.Contains(fmt.Sprint(delivered), "top-secret") {
		t.Fatal("delivery event leaked the secret value")
	}
	// The identity metadata records the vault location, not the secret.
	stored := store.List()
	if stored[0].Metadata["vault_secret"] != "mutandae-demo-ab12" || stored[0].Metadata["vault_version"] != "v1" {
		t.Fatalf("identity vault metadata = %+v", stored[0].Metadata)
	}
	if strings.Contains(fmt.Sprint(stored[0]), "top-secret") {
		t.Fatal("vault metadata leaked the secret value")
	}
}

func TestProvisionVaultFailureIsAuditedAndNonFatal(t *testing.T) {
	adapter := &vaultAdapter{
		provisioningAdapter: &provisioningAdapter{fakeAdapter: &fakeAdapter{}},
		failStore:           fmt.Errorf("vault unavailable"),
	}
	store := vaultTestStore(t, adapter)

	resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now())
	if err != nil {
		t.Fatalf("Provision with failing vault should still succeed: %v", err)
	}
	if resp.Vault != nil {
		t.Fatal("response must not claim a vault delivery that failed")
	}
	events, _ := store.Events(resp.Identity.ID)
	found := false
	for _, event := range events {
		if event.Type == protocol.EventCredentialDelivered && event.Outcome == protocol.OutcomeAttention {
			found = true
		}
	}
	if !found {
		t.Fatal("vault delivery failure was not audited as attention")
	}
}

func TestRotateDeliversRenewedSecretToVault(t *testing.T) {
	adapter := &vaultAdapter{provisioningAdapter: &provisioningAdapter{fakeAdapter: &fakeAdapter{}}, issued: "renewed-secret"}
	store := vaultTestStore(t, adapter)

	resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	id := resp.Identity.ID
	if _, err := store.Rotate(context.Background(), protocol.RotateRequest{ID: id, Reason: "test"}, now()); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	// The renewed secret reached the vault under the rotation's new key id.
	if got := adapter.stored["mutandae-demo-ab12|mutandae-demo-ab12-new-key"]; got != "renewed-secret" {
		t.Fatalf("vault stored renewed value = %q", got)
	}
	events, _ := store.Events(id)
	deliveries := 0
	for _, event := range events {
		if event.Type == protocol.EventCredentialDelivered && event.Outcome == protocol.OutcomeSuccess {
			deliveries++
		}
	}
	if deliveries != 2 {
		t.Fatalf("credential.delivered success events = %d, want 2 (provision + renewal)", deliveries)
	}
	stored, _ := store.Get(id)
	if stored.Metadata["vault_version"] != "v1" {
		t.Fatalf("vault version metadata = %q", stored.Metadata["vault_version"])
	}
}

func TestUseRetrievesFromVaultAndAuditsTheRetrieval(t *testing.T) {
	adapter := &vaultAdapter{provisioningAdapter: &provisioningAdapter{fakeAdapter: &fakeAdapter{}}}
	store := vaultTestStore(t, adapter)

	resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	id := resp.Identity.ID

	used, err := store.Use(context.Background(), protocol.UseRequest{ID: id, RequestedBy: "visitor"}, now())
	if err != nil {
		t.Fatalf("Use: %v", err)
	}
	if used.Secret != "top-secret" {
		t.Fatalf("Use secret = %q, want the vault copy", used.Secret)
	}
	if used.Vault == nil || used.Vault.SecretName != "mutandae-demo-ab12" {
		t.Fatalf("Use vault reference = %+v", used.Vault)
	}
	events, _ := store.Events(id)
	var usedEvent *protocol.LifecycleEvent
	for i := range events {
		if events[i].Type == protocol.EventCredentialUsed {
			usedEvent = &events[i]
			break
		}
	}
	if usedEvent == nil {
		t.Fatal("no credential.used event recorded")
	}
	if usedEvent.Actor != "visitor" || usedEvent.Outcome != protocol.OutcomeSuccess {
		t.Fatalf("used event = %+v", usedEvent)
	}
	if strings.Contains(fmt.Sprint(usedEvent), "top-secret") {
		t.Fatal("used event leaked the secret value")
	}
}

func TestUseRejectsRetiredAndUnknownIdentities(t *testing.T) {
	adapter := &vaultAdapter{provisioningAdapter: &provisioningAdapter{fakeAdapter: &fakeAdapter{}}}
	store := vaultTestStore(t, adapter)

	resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	id := resp.Identity.ID
	if _, err := store.Retire(context.Background(), protocol.RetireRequest{ID: id, Confirm: true}, now()); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if _, err := store.Use(context.Background(), protocol.UseRequest{ID: id}, now()); err == nil {
		t.Fatal("Use on a retired identity should be refused")
	}
	if _, err := store.Use(context.Background(), protocol.UseRequest{ID: "missing"}, now()); err == nil {
		t.Fatal("Use on an unknown identity should be refused")
	}
}

func TestUseWithoutVaultCapabilityIsRefused(t *testing.T) {
	store := testStore(t, &provisioningAdapter{fakeAdapter: &fakeAdapter{}})
	if _, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now()); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if _, err := store.Use(context.Background(), protocol.UseRequest{ID: "mutandae-demo-ab12"}, now()); err == nil {
		t.Fatal("Use without a vault-capable adapter should be refused")
	}
}

func TestRetireRevokesTheVaultCopy(t *testing.T) {
	adapter := &vaultAdapter{provisioningAdapter: &provisioningAdapter{fakeAdapter: &fakeAdapter{}}}
	store := vaultTestStore(t, adapter)

	resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	id := resp.Identity.ID
	if _, err := store.Retire(context.Background(), protocol.RetireRequest{ID: id, Confirm: true}, now()); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if len(adapter.revoked) != 1 || adapter.revoked[0] != "mutandae-demo-ab12" {
		t.Fatalf("vault revocations = %v", adapter.revoked)
	}
	events, _ := store.Events(id)
	revoked := false
	for _, event := range events {
		if event.Type == protocol.EventCredentialRevoked && event.Outcome == protocol.OutcomeSuccess {
			revoked = true
		}
	}
	if !revoked {
		t.Fatal("no credential.revoked event recorded")
	}
}

func TestRetireVaultRevocationFailureIsAuditedAndNonFatal(t *testing.T) {
	adapter := &vaultAdapter{
		provisioningAdapter: &provisioningAdapter{fakeAdapter: &fakeAdapter{}},
		failRevoke:          fmt.Errorf("vault read-only"),
	}
	store := vaultTestStore(t, adapter)

	resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	id := resp.Identity.ID
	if _, err := store.Retire(context.Background(), protocol.RetireRequest{ID: id, Confirm: true}, now()); err != nil {
		t.Fatalf("Retire should not fail on vault errors: %v", err)
	}
	events, _ := store.Events(id)
	attention := false
	for _, event := range events {
		if event.Type == protocol.EventCredentialRevoked && event.Outcome == protocol.OutcomeAttention {
			attention = true
		}
	}
	if !attention {
		t.Fatal("vault revocation failure was not audited as attention")
	}
}
