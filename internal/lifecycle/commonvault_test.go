package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// clusterVaultFake is an in-memory CommonVault fake standing in for the
// cluster μVault. Secret names are identity-scoped ("mutandae/<name>") and
// every StoreSecret call produces a new version of that secret, mirroring how
// a real cluster vault versions a credential across rotations. All counters
// and maps are mutex-guarded so tests stay race-clean under -race.
type clusterVaultFake struct {
	mu          sync.Mutex
	stored      map[string]string // secretName -> secret value
	versions    map[string]int    // secretName -> number of stored versions
	failStore   error
	failRead    error
	failRevoke  error
	unsupported bool // every capability reports ErrVaultUnsupported
	storeCalls  int
	readCalls   int
	revokeCalls int
	revoked     []string
}

func newClusterVaultFake() *clusterVaultFake {
	return &clusterVaultFake{stored: map[string]string{}, versions: map[string]int{}}
}

func (c *clusterVaultFake) secretName(identity protocol.MachineIdentity) string {
	return "mutandae/" + identity.Name
}

func (c *clusterVaultFake) StoreSecret(_ context.Context, identity protocol.MachineIdentity, _ string, secret string) (protocol.VaultReference, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.storeCalls++
	if c.unsupported {
		return protocol.VaultReference{}, ErrVaultUnsupported
	}
	if c.failStore != nil {
		return protocol.VaultReference{}, c.failStore
	}
	name := c.secretName(identity)
	c.versions[name]++
	c.stored[name] = secret
	return c.referenceLocked(name), nil
}

func (c *clusterVaultFake) ReadSecret(_ context.Context, identity protocol.MachineIdentity, _, _ string) (string, protocol.VaultReference, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readCalls++
	if c.unsupported {
		return "", protocol.VaultReference{}, ErrVaultUnsupported
	}
	if c.failRead != nil {
		return "", protocol.VaultReference{}, c.failRead
	}
	name := c.secretName(identity)
	value, ok := c.stored[name]
	if !ok {
		return "", protocol.VaultReference{}, fmt.Errorf("no cluster vault copy for %s", name)
	}
	return value, c.referenceLocked(name), nil
}

func (c *clusterVaultFake) RevokeSecret(_ context.Context, identity protocol.MachineIdentity, _ string) (protocol.VaultReference, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revokeCalls++
	if c.unsupported {
		return protocol.VaultReference{}, ErrVaultUnsupported
	}
	if c.failRevoke != nil {
		return protocol.VaultReference{}, c.failRevoke
	}
	name := c.secretName(identity)
	c.revoked = append(c.revoked, name)
	return c.referenceLocked(name), nil
}

// referenceLocked builds the redacted reference; callers hold c.mu.
func (c *clusterVaultFake) referenceLocked(name string) protocol.VaultReference {
	return protocol.VaultReference{
		URL:        "muvault://cluster",
		SecretName: name,
		Version:    fmt.Sprintf("v%d", c.versions[name]),
	}
}

func commonVaultStore(t *testing.T, adapter Adapter, commonVault CommonVault) *Store {
	t.Helper()
	store, err := NewStore(context.Background(), now(), adapter, WithCommonVault(commonVault))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	return store
}

// deliveredEvents returns every credential.delivered event on the trail.
func deliveredEvents(t *testing.T, store *Store, id string) []protocol.LifecycleEvent {
	t.Helper()
	events, ok := store.Events(id)
	if !ok {
		t.Fatalf("no event trail for %q", id)
	}
	var matched []protocol.LifecycleEvent
	for _, event := range events {
		if event.Type == protocol.EventCredentialDelivered {
			matched = append(matched, event)
		}
	}
	return matched
}

// revokedEvents returns every credential.revoked event on the trail.
func revokedEvents(t *testing.T, store *Store, id string) []protocol.LifecycleEvent {
	t.Helper()
	events, ok := store.Events(id)
	if !ok {
		t.Fatalf("no event trail for %q", id)
	}
	var matched []protocol.LifecycleEvent
	for _, event := range events {
		if event.Type == protocol.EventCredentialRevoked {
			matched = append(matched, event)
		}
	}
	return matched
}

func usedEvent(t *testing.T, store *Store, id string) protocol.LifecycleEvent {
	t.Helper()
	events, ok := store.Events(id)
	if !ok {
		t.Fatalf("no event trail for %q", id)
	}
	for _, event := range events {
		if event.Type == protocol.EventCredentialUsed {
			return event
		}
	}
	t.Fatal("no credential.used event recorded")
	return protocol.LifecycleEvent{}
}

// usedEventExists reports whether the trail already carries a
// credential.used event; failed retrievals must never record one.
func usedEventExists(store *Store, id string) bool {
	events, ok := store.Events(id)
	if !ok {
		return false
	}
	for _, event := range events {
		if event.Type == protocol.EventCredentialUsed {
			return true
		}
	}
	return false
}

// isClusterDelivery classifies an audit event as a cluster μVault operation:
// both cluster successes and failures carry the vault_kind detail, and native
// vault events never do.
func isClusterDelivery(event protocol.LifecycleEvent) bool {
	return event.Details["vault_kind"] == commonVaultKind
}

func TestProvisionMirrorsToCommonVaultWhileKeepingNativeReference(t *testing.T) {
	t.Parallel()
	adapter := &vaultAdapter{provisioningAdapter: &provisioningAdapter{fakeAdapter: &fakeAdapter{}}}
	common := newClusterVaultFake()
	store := commonVaultStore(t, adapter, common)

	resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam", Purpose: "demo"}, now())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	// The response advertises the native reference, not the mirror.
	if resp.Vault == nil || resp.Vault.URL != "vault://test" || resp.Vault.SecretName != "mutandae-demo-ab12" {
		t.Fatalf("resp.Vault = %+v, want the native reference", resp.Vault)
	}
	// The identity metadata carries both key sets independently.
	metadata := resp.Identity.Metadata
	want := map[string]string{
		"vault_url":            "vault://test",
		"vault_secret":         "mutandae-demo-ab12",
		"vault_version":        "v1",
		"common_vault_url":     "muvault://cluster",
		"common_vault_secret":  "mutandae/mutandae-demo-ab12",
		"common_vault_version": "v1",
	}
	for key, wantValue := range want {
		if metadata[key] != wantValue {
			t.Errorf("metadata[%q] = %q, want %q", key, metadata[key], wantValue)
		}
	}
	// Both deliveries appear as independent, successful audit events.
	delivered := deliveredEvents(t, store, resp.Identity.ID)
	native, cluster := 0, 0
	for _, event := range delivered {
		if event.Outcome != protocol.OutcomeSuccess {
			t.Errorf("delivered event outcome = %q, want success", event.Outcome)
		}
		if isClusterDelivery(event) {
			cluster++
			if event.Details["vault_kind"] != commonVaultKind {
				t.Errorf("cluster event vault_kind = %q, want %q", event.Details["vault_kind"], commonVaultKind)
			}
		} else {
			native++
		}
		if strings.Contains(fmt.Sprint(event), "top-secret") {
			t.Fatal("delivery event leaked the secret value")
		}
	}
	if native != 1 || cluster != 1 {
		t.Fatalf("delivered events = %d native, %d cluster; want 1 of each", native, cluster)
	}
	if strings.Contains(fmt.Sprint(metadata), "top-secret") {
		t.Fatal("vault metadata leaked the secret value")
	}
	if common.storeCalls != 1 {
		t.Fatalf("cluster vault store calls = %d, want 1", common.storeCalls)
	}
}

func TestProvisionFallsBackToCommonVaultWhenNativeUnsupported(t *testing.T) {
	t.Parallel()
	// The adapter has no VaultStore capability at all, so the cluster μVault
	// copy is the only retrievable reference.
	adapter := &provisioningAdapter{fakeAdapter: &fakeAdapter{}}
	common := newClusterVaultFake()
	store := commonVaultStore(t, adapter, common)

	resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now())
	if err != nil {
		t.Fatalf("Provision with only a cluster vault should succeed: %v", err)
	}
	if resp.Vault == nil || resp.Vault.URL != "muvault://cluster" || resp.Vault.Version != "v1" {
		t.Fatalf("resp.Vault = %+v, want the common reference", resp.Vault)
	}
	metadata := resp.Identity.Metadata
	if metadata["common_vault_secret"] != "mutandae/mutandae-demo-ab12" || metadata["common_vault_version"] != "v1" {
		t.Fatalf("common metadata = %+v", metadata)
	}
	for _, nativeKey := range []string{"vault_url", "vault_secret", "vault_version"} {
		if _, ok := metadata[nativeKey]; ok {
			t.Errorf("metadata carries native key %q without a native delivery", nativeKey)
		}
	}
	delivered := deliveredEvents(t, store, resp.Identity.ID)
	if len(delivered) != 1 || !isClusterDelivery(delivered[0]) || delivered[0].Outcome != protocol.OutcomeSuccess {
		t.Fatalf("delivered events = %+v, want exactly one successful mirror event", delivered)
	}
	if common.storeCalls != 1 {
		t.Fatalf("cluster vault store calls = %d, want 1", common.storeCalls)
	}
}

func TestProvisionCommonMirrorFailureIsAuditedAndNonFatal(t *testing.T) {
	t.Parallel()
	adapter := &vaultAdapter{provisioningAdapter: &provisioningAdapter{fakeAdapter: &fakeAdapter{}}}
	common := newClusterVaultFake()
	common.failStore = errors.New("cluster vault unavailable")
	store := commonVaultStore(t, adapter, common)

	resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now())
	if err != nil {
		t.Fatalf("Provision with a failing mirror should still succeed: %v", err)
	}
	// The native reference and metadata are untouched by the mirror failure.
	if resp.Vault == nil || resp.Vault.URL != "vault://test" {
		t.Fatalf("resp.Vault = %+v, want the native reference", resp.Vault)
	}
	metadata := resp.Identity.Metadata
	if metadata["vault_secret"] != "mutandae-demo-ab12" || metadata["vault_version"] != "v1" {
		t.Fatalf("native metadata = %+v", metadata)
	}
	if _, ok := metadata["common_vault_secret"]; ok {
		t.Fatal("metadata must not claim a cluster copy that failed to store")
	}
	delivered := deliveredEvents(t, store, resp.Identity.ID)
	var attention int
	for _, event := range delivered {
		switch {
		case event.Outcome == protocol.OutcomeSuccess && !isClusterDelivery(event):
			// The native delivery succeeded.
		case event.Outcome == protocol.OutcomeAttention && isClusterDelivery(event):
			attention++
			if !strings.HasPrefix(event.Summary, "Cluster vault delivery failed: ") {
				t.Errorf("mirror failure summary = %q", event.Summary)
			}
			if event.Details["error"] != "cluster vault unavailable" {
				t.Errorf("mirror failure error detail = %q", event.Details["error"])
			}
		default:
			t.Errorf("unexpected delivered event: %+v", event)
		}
	}
	if attention != 1 {
		t.Fatalf("mirror failure attention events = %d, want 1", attention)
	}
}

func TestRotateStoresAndAuditsNewCommonVaultVersion(t *testing.T) {
	t.Parallel()
	adapter := &vaultAdapter{provisioningAdapter: &provisioningAdapter{fakeAdapter: &fakeAdapter{}}, issued: "renewed-secret"}
	common := newClusterVaultFake()
	store := commonVaultStore(t, adapter, common)

	provisioned, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	id := provisioned.Identity.ID
	if stored, _ := store.Get(id); stored.Metadata["common_vault_version"] != "v1" {
		t.Fatalf("provisioned common vault version = %q, want v1", stored.Metadata["common_vault_version"])
	}
	if _, err := store.Rotate(context.Background(), protocol.RotateRequest{ID: id, Reason: "test"}, now()); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	// The renewed credential became a new version of the cluster μVault copy.
	stored, _ := store.Get(id)
	if stored.Metadata["common_vault_version"] != "v2" {
		t.Fatalf("common vault version after rotation = %q, want v2", stored.Metadata["common_vault_version"])
	}
	if stored.Metadata["common_vault_secret"] != "mutandae/mutandae-demo-ab12" {
		t.Fatalf("common vault secret = %q", stored.Metadata["common_vault_secret"])
	}
	if stored.Metadata["vault_version"] != "v1" {
		t.Fatalf("native vault version = %q, want the untouched native v1", stored.Metadata["vault_version"])
	}
	delivered := deliveredEvents(t, store, id)
	native, cluster := 0, 0
	for _, event := range delivered {
		if event.Outcome != protocol.OutcomeSuccess {
			continue
		}
		if isClusterDelivery(event) {
			cluster++
		} else {
			native++
		}
	}
	if native != 2 || cluster != 2 {
		t.Fatalf("delivered success events = %d native, %d cluster; want 2 of each (provision + renewal)", native, cluster)
	}
	if common.storeCalls != 2 {
		t.Fatalf("cluster vault store calls = %d, want 2", common.storeCalls)
	}
}

func TestUsePrefersNativeVaultAndLeavesClusterVaultUntouched(t *testing.T) {
	t.Parallel()
	adapter := &vaultAdapter{provisioningAdapter: &provisioningAdapter{fakeAdapter: &fakeAdapter{}}}
	common := newClusterVaultFake()
	store := commonVaultStore(t, adapter, common)

	resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	used, err := store.Use(context.Background(), protocol.UseRequest{ID: resp.Identity.ID, RequestedBy: "visitor"}, now())
	if err != nil {
		t.Fatalf("Use: %v", err)
	}
	if used.Secret != "top-secret" || used.Vault == nil || used.Vault.URL != "vault://test" {
		t.Fatalf("Use = (secret %q, vault %+v), want the native copy", used.Secret, used.Vault)
	}
	if common.readCalls != 0 {
		t.Fatalf("cluster vault read calls = %d, want 0: a native success must not consult the mirror", common.readCalls)
	}
	event := usedEvent(t, store, resp.Identity.ID)
	if event.Summary != "Credential retrieved from the AWS Secrets Manager by visitor" {
		t.Fatalf("used event summary = %q", event.Summary)
	}
	if _, ok := event.Details["common_vault_secret"]; ok {
		t.Fatal("native retrieval must not record cluster vault details")
	}
	if _, ok := event.Details["vault_kind"]; ok {
		t.Fatal("native retrieval must not record a cluster vault kind")
	}
}

func TestUseFallsBackToClusterVaultWhenNativeUnsupported(t *testing.T) {
	t.Parallel()
	// Every native vault operation reports ErrVaultUnsupported, so Use must
	// fall back to the cluster μVault copy recorded at delivery time.
	adapter := &disabledVaultAdapter{provisioningAdapter: &provisioningAdapter{fakeAdapter: &fakeAdapter{}}}
	common := newClusterVaultFake()
	store := commonVaultStore(t, adapter, common)

	resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	used, err := store.Use(context.Background(), protocol.UseRequest{ID: resp.Identity.ID, RequestedBy: "visitor"}, now())
	if err != nil {
		t.Fatalf("Use with a cluster μVault fallback: %v", err)
	}
	if used.Secret != "top-secret" || used.Vault == nil || used.Vault.URL != "muvault://cluster" {
		t.Fatalf("Use = (secret %q, vault %+v), want the cluster copy", used.Secret, used.Vault)
	}
	event := usedEvent(t, store, resp.Identity.ID)
	if event.Summary != "Credential retrieved from the cluster μVault vault by visitor" {
		t.Fatalf("used event summary = %q", event.Summary)
	}
	want := map[string]string{
		"vault_kind":           commonVaultKind,
		"common_vault_secret":  "mutandae/mutandae-demo-ab12",
		"common_vault_version": "v1",
	}
	for key, wantValue := range want {
		if event.Details[key] != wantValue {
			t.Errorf("used event details[%q] = %q, want %q", key, event.Details[key], wantValue)
		}
	}
	for _, nativeKey := range []string{"vault_secret", "vault_version", "vault_url"} {
		if _, ok := event.Details[nativeKey]; ok {
			t.Errorf("fallback retrieval must not record native key %q", nativeKey)
		}
	}
	if strings.Contains(fmt.Sprint(event), "top-secret") {
		t.Fatal("used event leaked the secret value")
	}
}

func TestUseFallsBackToClusterVaultWithoutNativeCapability(t *testing.T) {
	t.Parallel()
	// The adapter has no VaultStore capability at all (the control plane sees
	// no native vault), so the cluster μVault is the only source.
	adapter := &provisioningAdapter{fakeAdapter: &fakeAdapter{}}
	common := newClusterVaultFake()
	store := commonVaultStore(t, adapter, common)

	resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	used, err := store.Use(context.Background(), protocol.UseRequest{ID: resp.Identity.ID, RequestedBy: "visitor"}, now())
	if err != nil {
		t.Fatalf("Use: %v", err)
	}
	if used.Secret != "top-secret" || used.Vault == nil || used.Vault.URL != "muvault://cluster" {
		t.Fatalf("Use = (secret %q, vault %+v), want the cluster copy", used.Secret, used.Vault)
	}
	if common.readCalls != 1 {
		t.Fatalf("cluster vault read calls = %d, want 1", common.readCalls)
	}
	event := usedEvent(t, store, resp.Identity.ID)
	if event.Summary != "Credential retrieved from the cluster μVault vault by visitor" {
		t.Fatalf("used event summary = %q", event.Summary)
	}
}

func TestUseNativeOutageDoesNotSilentlySwitchVaults(t *testing.T) {
	t.Parallel()
	adapter := &vaultAdapter{provisioningAdapter: &provisioningAdapter{fakeAdapter: &fakeAdapter{}}, failRead: errors.New("key vault throttled")}
	common := newClusterVaultFake()
	store := commonVaultStore(t, adapter, common)

	resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	_, err = store.Use(context.Background(), protocol.UseRequest{ID: resp.Identity.ID}, now())
	if !errors.Is(err, ErrProviderFailure) {
		t.Fatalf("Use error = %v, want ErrProviderFailure", err)
	}
	if common.readCalls != 0 {
		t.Fatalf("cluster vault read calls = %d, want 0: a native outage must not switch vaults", common.readCalls)
	}
	if usedEventExists(store, resp.Identity.ID) {
		t.Fatal("a failed retrieval must not record a credential.used event")
	}
}

func TestUseClusterFallbackFailureSurfacesProviderFailure(t *testing.T) {
	t.Parallel()
	adapter := &disabledVaultAdapter{provisioningAdapter: &provisioningAdapter{fakeAdapter: &fakeAdapter{}}}
	common := newClusterVaultFake()
	common.failRead = errors.New("cluster vault sealed")
	store := commonVaultStore(t, adapter, common)

	resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	_, err = store.Use(context.Background(), protocol.UseRequest{ID: resp.Identity.ID}, now())
	if !errors.Is(err, ErrProviderFailure) {
		t.Fatalf("Use error = %v, want ErrProviderFailure for a failing cluster fallback", err)
	}
	if usedEventExists(store, resp.Identity.ID) {
		t.Fatal("a failed retrieval must not record a credential.used event")
	}
}

func TestUseWithoutAnyVaultCapabilityKeepsExistingError(t *testing.T) {
	t.Parallel()
	// No native capability and no cluster vault: today's bare refusal.
	store := testStore(t, &provisioningAdapter{fakeAdapter: &fakeAdapter{}})
	resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if resp.Vault != nil {
		t.Fatal("no vault is configured, so the response must not claim one")
	}
	_, err = store.Use(context.Background(), protocol.UseRequest{ID: resp.Identity.ID}, now())
	if !errors.Is(err, ErrVaultUnsupported) || errors.Is(err, ErrProviderFailure) {
		t.Fatalf("Use error = %v, want the bare ErrVaultUnsupported", err)
	}
}

func TestWithCommonVaultNilOptionIsInert(t *testing.T) {
	t.Parallel()
	adapter := &vaultAdapter{provisioningAdapter: &provisioningAdapter{fakeAdapter: &fakeAdapter{}}}
	store := commonVaultStore(t, adapter, nil)

	resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if resp.Vault == nil || resp.Vault.URL != "vault://test" {
		t.Fatalf("resp.Vault = %+v, want the native reference", resp.Vault)
	}
	metadata := resp.Identity.Metadata
	if metadata["vault_secret"] != "mutandae-demo-ab12" {
		t.Fatalf("native metadata = %+v", metadata)
	}
	for _, commonKey := range []string{"common_vault_url", "common_vault_secret", "common_vault_version"} {
		if _, ok := metadata[commonKey]; ok {
			t.Errorf("metadata carries %q without a configured cluster vault", commonKey)
		}
	}
	delivered := deliveredEvents(t, store, resp.Identity.ID)
	if len(delivered) != 1 || isClusterDelivery(delivered[0]) {
		t.Fatalf("delivered events = %+v, want exactly the native delivery", delivered)
	}
	used, err := store.Use(context.Background(), protocol.UseRequest{ID: resp.Identity.ID, RequestedBy: "visitor"}, now())
	if err != nil {
		t.Fatalf("Use: %v", err)
	}
	if used.Secret != "top-secret" {
		t.Fatalf("Use secret = %q", used.Secret)
	}
}

func TestRetireRevokesBothVaultCopies(t *testing.T) {
	t.Parallel()
	adapter := &vaultAdapter{provisioningAdapter: &provisioningAdapter{fakeAdapter: &fakeAdapter{}}}
	common := newClusterVaultFake()
	store := commonVaultStore(t, adapter, common)

	resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	id := resp.Identity.ID
	if _, err := store.Retire(context.Background(), protocol.RetireRequest{ID: id, Confirm: true}, now()); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if len(adapter.revoked) != 1 || adapter.revoked[0] != "mutandae-demo-ab12" {
		t.Fatalf("native vault revocations = %v", adapter.revoked)
	}
	if common.revokeCalls != 1 || len(common.revoked) != 1 || common.revoked[0] != "mutandae/mutandae-demo-ab12" {
		t.Fatalf("cluster vault revocations = %d (%v)", common.revokeCalls, common.revoked)
	}
	events := revokedEvents(t, store, id)
	var native, cluster int
	for _, event := range events {
		if event.Outcome != protocol.OutcomeSuccess {
			t.Errorf("revoked event outcome = %q, want success", event.Outcome)
		}
		if event.Details["common_vault_secret"] != "" {
			cluster++
			if event.Summary != "Cluster vault copy removed (μVault)" {
				t.Errorf("cluster revocation summary = %q", event.Summary)
			}
			if event.Details["vault_kind"] != commonVaultKind {
				t.Errorf("cluster revocation vault_kind = %q", event.Details["vault_kind"])
			}
		} else {
			native++
		}
	}
	if native != 1 || cluster != 1 {
		t.Fatalf("revoked events = %d native, %d cluster; want 1 of each", native, cluster)
	}
}

func TestRetireCommonRevocationFailureIsAuditedAndRetirementSucceeds(t *testing.T) {
	t.Parallel()
	adapter := &vaultAdapter{provisioningAdapter: &provisioningAdapter{fakeAdapter: &fakeAdapter{}}}
	common := newClusterVaultFake()
	common.failRevoke = errors.New("cluster vault read-only")
	store := commonVaultStore(t, adapter, common)

	resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	id := resp.Identity.ID
	if _, err := store.Retire(context.Background(), protocol.RetireRequest{ID: id, Confirm: true}, now()); err != nil {
		t.Fatalf("Retire should not fail on cluster vault errors: %v", err)
	}
	// The native revocation still ran.
	if len(adapter.revoked) != 1 {
		t.Fatalf("native vault revocations = %v", adapter.revoked)
	}
	var attention, success int
	for _, event := range revokedEvents(t, store, id) {
		switch {
		case event.Outcome == protocol.OutcomeAttention:
			attention++
			if !strings.HasPrefix(event.Summary, "Cluster vault revocation failed: ") {
				t.Errorf("cluster revocation failure summary = %q", event.Summary)
			}
			if event.Details["error"] != "cluster vault read-only" {
				t.Errorf("cluster revocation failure error = %q", event.Details["error"])
			}
		case event.Outcome == protocol.OutcomeSuccess && !isClusterDelivery(event):
			success++ // the native success event
		default:
			t.Errorf("unexpected revoked event: %+v", event)
		}
	}
	if attention != 1 || success != 1 {
		t.Fatalf("revoked events = %d attention, %d native success; want 1 of each", attention, success)
	}
}

func TestRetireSkipsSilentClusterVaultWhenUnsupported(t *testing.T) {
	t.Parallel()
	adapter := &vaultAdapter{provisioningAdapter: &provisioningAdapter{fakeAdapter: &fakeAdapter{}}}
	common := newClusterVaultFake()
	common.unsupported = true
	store := commonVaultStore(t, adapter, common)

	resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	id := resp.Identity.ID
	// The unsupported mirror is silent at delivery time too.
	if delivered := deliveredEvents(t, store, id); len(delivered) != 1 || isClusterDelivery(delivered[0]) {
		t.Fatalf("delivered events = %+v, want only the native delivery", delivered)
	}
	if _, err := store.Retire(context.Background(), protocol.RetireRequest{ID: id, Confirm: true}, now()); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	for _, event := range revokedEvents(t, store, id) {
		if event.Details["common_vault_secret"] != "" || isClusterDelivery(event) || strings.Contains(event.Summary, "Cluster vault") {
			t.Fatalf("unsupported cluster vault must be silently skipped, got %+v", event)
		}
		if event.Outcome != protocol.OutcomeSuccess {
			t.Fatalf("only the native success should remain, got %+v", event)
		}
	}
}

func TestConcurrentLifecycleWithClusterVaultIsDeterministic(t *testing.T) {
	t.Parallel()
	adapter := &vaultAdapter{provisioningAdapter: &provisioningAdapter{fakeAdapter: &fakeAdapter{}}, issued: "renewed-secret"}
	common := newClusterVaultFake()
	store := commonVaultStore(t, adapter, common)

	const goroutines = 8
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now())
			if err != nil {
				errCh <- err
				return
			}
			used, err := store.Use(context.Background(), protocol.UseRequest{ID: resp.Identity.ID}, now())
			if err != nil {
				errCh <- err
				return
			}
			if used.Secret != "top-secret" {
				errCh <- fmt.Errorf("use secret = %q", used.Secret)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent provision/use: %v", err)
	}
	// The shared fake issues one identity id, so every provision appends one
	// native and one cluster delivery, and every use appends one native read.
	id := "mutandae-demo-ab12"
	delivered, clusterDelivered, used := 0, 0, 0
	events, _ := store.Events(id)
	for _, event := range events {
		switch event.Type {
		case protocol.EventCredentialDelivered:
			delivered++
			if isClusterDelivery(event) {
				clusterDelivered++
			}
		case protocol.EventCredentialUsed:
			used++
		}
	}
	if delivered != 2*goroutines || clusterDelivered != goroutines || used != goroutines {
		t.Fatalf("events = %d delivered (%d cluster), %d used; want %d delivered (%d cluster), %d used",
			delivered, clusterDelivered, used, 2*goroutines, goroutines, goroutines)
	}
	if common.readCalls != 0 {
		t.Fatalf("cluster vault read calls = %d, want 0: uses must be served natively", common.readCalls)
	}

	// Sequential rotate and retire keep both vaults in step.
	if _, err := store.Rotate(context.Background(), protocol.RotateRequest{ID: id, Reason: "race-check"}, now()); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if _, err := store.Retire(context.Background(), protocol.RetireRequest{ID: id, Confirm: true}, now()); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if common.storeCalls != goroutines+1 {
		t.Fatalf("cluster vault store calls = %d, want %d", common.storeCalls, goroutines+1)
	}
	if common.revokeCalls != 1 {
		t.Fatalf("cluster vault revoke calls = %d, want 1", common.revokeCalls)
	}
	stored, _ := store.Get(id)
	if got := stored.Metadata["common_vault_version"]; got != fmt.Sprintf("v%d", goroutines+1) {
		t.Fatalf("common vault version after %d mirrors + 1 rotation = %q", goroutines, got)
	}
	revoked := 0
	events, _ = store.Events(id)
	for _, event := range events {
		if event.Type == protocol.EventCredentialRevoked && event.Outcome == protocol.OutcomeSuccess {
			revoked++
		}
	}
	if revoked != 2 {
		t.Fatalf("successful revocation events = %d, want 2 (native + cluster)", revoked)
	}
}

// TestUseFallsBackOnWrappedNativeUnsupported locks the cross-package sentinel
// contract: adapters wrap ErrVaultUnsupported with context (fmt.Errorf %w) and
// the control plane must still recognize it as "native capability absent" and
// serve the credential from the cluster μVault copy.
func TestUseFallsBackOnWrappedNativeUnsupported(t *testing.T) {
	t.Parallel()
	adapter := &wrappedUnsupportedVaultAdapter{provisioningAdapter: &provisioningAdapter{fakeAdapter: &fakeAdapter{}}}
	common := newClusterVaultFake()
	store := commonVaultStore(t, adapter, common)

	resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	used, err := store.Use(context.Background(), protocol.UseRequest{ID: resp.Identity.ID, RequestedBy: "visitor"}, now())
	if err != nil {
		t.Fatalf("Use with a wrapped unsupported native vault: %v", err)
	}
	if used.Secret != "top-secret" || used.Vault == nil || used.Vault.URL != "muvault://cluster" {
		t.Fatalf("Use = (secret %q, vault %+v), want the cluster copy", used.Secret, used.Vault)
	}
	if usedEvent(t, store, resp.Identity.ID).Details["vault_kind"] != commonVaultKind {
		t.Fatal("fallback retrieval must be audited as a cluster vault read")
	}
}
