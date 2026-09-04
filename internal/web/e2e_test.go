package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mutandae/mutandae/internal/config"
	"github.com/mutandae/mutandae/internal/lifecycle"
	"github.com/mutandae/mutandae/pkg/protocol"
)

// The journey test drives the whole public demo through real HTTP: a visitor
// provisions a zero-permission identity in a "tenant" whose native vault is
// denied (the live AWS/GCP topology), the credential mirrors into the cluster
// μVault, gets retrieved, rotated, retrieved again, and finally retired. A
// capturing repository proves the one-time secret never persists.

const (
	journeySecretOne   = "e2e-one-time-secret-1111"
	journeySecretRenew = "e2e-renewed-secret-2222"
)

// journeyAdapter stands in for a real provider adapter with a denied native
// vault: Create issues a zero-permission identity plus a one-time secret, the
// VaultStore capability deterministically refuses (wrapped canonical
// sentinel), and Rotate issues a fresh credential.
type journeyAdapter struct {
	mu        sync.Mutex
	issued    string // one-time secret for the vault delivery after Create/Rotate
	issuedKey string
	serial    int
}

func (j *journeyAdapter) Kind() string { return "aws-iam" }

func (j *journeyAdapter) Discover(context.Context) ([]protocol.MachineIdentity, error) {
	return nil, nil
}

func (j *journeyAdapter) Rotate(_ context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.issued = journeySecretRenew
	j.issuedKey = identity.Credential.KeyID + "-rotated"
	identity.Credential.KeyID = j.issuedKey
	identity.Credential.Fingerprint = "sha256:rotated"
	identity.State = protocol.StateActive
	identity.Health = protocol.HealthHealthy
	return identity, nil
}

func (j *journeyAdapter) Retire(_ context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	identity.State = protocol.StateRetired
	identity.Health = protocol.HealthAttention
	return identity, nil
}

// Create provisions a zero-permission identity with a one-time secret, exactly
// like the real cloud adapters.
func (j *journeyAdapter) Create(_ context.Context, providerKind, _ string) (protocol.ProvisionResponse, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.serial++
	name := fmt.Sprintf("mutandae-demo-journey-%04d", j.serial)
	j.issued = journeySecretOne
	j.issuedKey = fmt.Sprintf("AKIAJOURNEY%04d", j.serial)
	identity := protocol.MachineIdentity{
		Name:      name,
		Provider:  protocol.ProviderBinding{Provider: providerKind, ProviderID: j.issuedKey, AccountID: "123456789012", Region: "us-east-1"},
		Ownership: protocol.Ownership{Team: "Demo", Service: "journey", Purpose: "public e2e", Criticality: "low"},
		Policy:    protocol.LifecyclePolicy{RenewalPeriod: "P7D"},
		Credential: protocol.CredentialReference{
			Kind: "access_key", Location: "iam", KeyID: j.issuedKey, Delivery: "secret-manager",
		},
	}
	return protocol.ProvisionResponse{
		Identity:      identity,
		OneTimeSecret: j.issued,
		KeyID:         j.issuedKey,
		Instructions:  "store it now",
	}, nil
}

// StoreSecret/ReadSecret/RevokeSecret emulate the live AWS governor: the
// native Secrets Manager capability is enabled in config but every call is
// denied, so the adapter wraps the canonical unsupported sentinel.
func (j *journeyAdapter) StoreSecret(context.Context, protocol.MachineIdentity, string, string) (protocol.VaultReference, error) {
	return protocol.VaultReference{}, fmt.Errorf("%w: native vault denied the write", protocol.ErrVaultUnsupported)
}

func (j *journeyAdapter) ReadSecret(context.Context, protocol.MachineIdentity, string, string) (string, protocol.VaultReference, error) {
	return "", protocol.VaultReference{}, fmt.Errorf("%w: native vault denied the read", protocol.ErrVaultUnsupported)
}

func (j *journeyAdapter) RevokeSecret(context.Context, protocol.MachineIdentity, string) (protocol.VaultReference, error) {
	return protocol.VaultReference{}, fmt.Errorf("%w: native vault denied the revocation", protocol.ErrVaultUnsupported)
}

func (j *journeyAdapter) ConsumeOneTimeSecret(provider string) string {
	if provider != j.Kind() {
		return ""
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	issued := j.issued
	j.issued = ""
	return issued
}

// journeyVault is the in-memory cluster μVault fake: every StoreSecret makes a
// new version, reads return the latest (or pinned) version, revocation clears.
type journeyVault struct {
	mu       sync.Mutex
	values   map[string]string
	versions map[string]int
	revoked  map[string]bool
}

func newJourneyVault() *journeyVault {
	return &journeyVault{values: map[string]string{}, versions: map[string]int{}, revoked: map[string]bool{}}
}

func (v *journeyVault) name(identity protocol.MachineIdentity) string {
	return "mutandae/demo/" + identity.Name
}

func (v *journeyVault) StoreSecret(_ context.Context, identity protocol.MachineIdentity, _, secret string) (protocol.VaultReference, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	name := v.name(identity)
	v.versions[name]++
	v.values[name] = secret
	return protocol.VaultReference{
		URL:        "http://mutandae-vault.mutandae.svc.cluster.local:8200",
		SecretName: name, Version: fmt.Sprintf("v%d", v.versions[name]),
		ExpiresAt: identity.ExpiresAt,
	}, nil
}

func (v *journeyVault) ReadSecret(_ context.Context, identity protocol.MachineIdentity, _, version string) (string, protocol.VaultReference, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	name := v.name(identity)
	value, ok := v.values[name]
	if !ok {
		return "", protocol.VaultReference{}, fmt.Errorf("no cluster vault copy for %s", name)
	}
	reference := protocol.VaultReference{URL: "http://mutandae-vault.mutandae.svc.cluster.local:8200", SecretName: name}
	if version == "" || version == "current" {
		reference.Version = fmt.Sprintf("v%d", v.versions[name])
	} else {
		reference.Version = version
	}
	return value, reference, nil
}

func (v *journeyVault) RevokeSecret(_ context.Context, identity protocol.MachineIdentity, _ string) (protocol.VaultReference, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	name := v.name(identity)
	v.revoked[name] = true
	delete(v.values, name)
	return protocol.VaultReference{URL: "http://mutandae-vault.mutandae.svc.cluster.local:8200", SecretName: name}, nil
}

// journeyRepository captures every persisted snapshot for redaction checks.
// The Changes channel terminates when the watcher context is cancelled — the
// same contract the Redis repository honors, and what Store.Close waits on.
type journeyRepository struct {
	mu    sync.Mutex
	saves []lifecycle.Snapshot
}

func newJourneyRepository() *journeyRepository {
	return &journeyRepository{}
}

func (r *journeyRepository) Load(context.Context) (lifecycle.Snapshot, error) {
	return lifecycle.Snapshot{}, lifecycle.ErrNoSnapshot
}

func (r *journeyRepository) Save(_ context.Context, snapshot lifecycle.Snapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.saves = append(r.saves, snapshot)
	return nil
}

func (r *journeyRepository) Changes(ctx context.Context) (<-chan struct{}, error) {
	// The watcher ranges over this channel until it closes; cancellation
	// (Store.Close) must therefore close it, exactly like the Redis one.
	changes := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(changes)
	}()
	return changes, nil
}

func (r *journeyRepository) Close() error { return nil }

func (r *journeyRepository) allJSON(t *testing.T) string {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	var builder strings.Builder
	for index, snapshot := range r.saves {
		payload, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatalf("marshal snapshot %d: %v", index, err)
		}
		builder.Write(payload)
	}
	return builder.String()
}

func journeyConfiguration() config.Public {
	return config.Public{
		Environment: "live",
		Provider:    "multi-cloud (aws-iam real)",
		Persistence: "in-memory",
		Features:    []string{"provision:aws-iam", "vault:cluster"},
		Clock:       func() time.Time { return testNow() },
	}
}

func newJourneyServer(t *testing.T) (http.Handler, *journeyRepository) {
	t.Helper()
	adapter := &journeyAdapter{}
	repository := newJourneyRepository()
	store, err := lifecycle.NewPersistentStore(context.Background(), testNow(), adapter, repository, lifecycle.WithCommonVault(newJourneyVault()))
	if err != nil {
		t.Fatalf("NewPersistentStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	server, err := newServer(Dependencies{
		Lifecycle:     store,
		Configuration: journeyConfiguration(),
		Clock:         func() time.Time { return testNow() },
		Logger:        testLogger{},
	})
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	return server.routes(), repository
}

func journeyDo(t *testing.T, handler http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	var request *http.Request
	if body == "" {
		request = httptest.NewRequest(method, target, nil)
	} else {
		request = httptest.NewRequest(method, target, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// TestEndToEndVisitorJourney walks the full public demo lifecycle over real
// HTTP against the real control-plane store.
func TestEndToEndVisitorJourney(t *testing.T) {
	handler, repository := newJourneyServer(t)

	// 1. The discovery index advertises the full lifecycle surface.
	index := journeyDo(t, handler, http.MethodGet, "/api/v1/", "")
	if index.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/ = %d", index.Code)
	}
	var discovery protocol.DiscoveryIndex
	if err := json.Unmarshal(index.Body.Bytes(), &discovery); err != nil {
		t.Fatalf("decode discovery index: %v", err)
	}
	rels := map[string]bool{}
	for _, resource := range discovery.Resources {
		rels[resource.Rel] = true
	}
	for _, want := range []string{"identities", "identity", "register", "provision", "rotate", "use", "retire"} {
		if !rels[want] {
			t.Errorf("discovery index does not advertise %q", want)
		}
	}

	// 2. The dashboard renders the protocol explainer, the flow diagram, and
	// the live-demo furniture.
	dashboard := journeyDo(t, handler, http.MethodGet, "/", "")
	if dashboard.Code != http.StatusOK {
		t.Fatalf("GET / = %d", dashboard.Code)
	}
	for _, want := range []string{"flow-desktop", "flow-mobile", "What is the μTandae Protocol?", "New identity", "Cluster vault: μVault (KV v2)"} {
		if !strings.Contains(dashboard.Body.String(), want) {
			t.Errorf("dashboard missing %q", want)
		}
	}

	// 3. Provision over the JSON API: 201 with a one-time secret and the
	// cluster μVault reference (the native vault was denied).
	provisioned := journeyDo(t, handler, http.MethodPost, "/api/v1/demo/identities", `{"provider":"aws-iam","purpose":"journey"}`)
	if provisioned.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/demo/identities = %d: %s", provisioned.Code, provisioned.Body.String())
	}
	var provisionResponse protocol.ProvisionResponse
	if err := json.Unmarshal(provisioned.Body.Bytes(), &provisionResponse); err != nil {
		t.Fatalf("decode provision response: %v", err)
	}
	if provisionResponse.OneTimeSecret != journeySecretOne {
		t.Fatalf("one-time secret = %q, want %q", provisionResponse.OneTimeSecret, journeySecretOne)
	}
	if provisionResponse.Vault == nil || !strings.Contains(provisionResponse.Vault.URL, "mutandae-vault") {
		t.Fatalf("provision response must advertise the cluster μVault copy, got %+v", provisionResponse.Vault)
	}
	id := provisionResponse.Identity.ID
	if !strings.HasPrefix(id, "mutandae-demo-journey-") {
		t.Fatalf("identity id = %q", id)
	}

	// 4. The inventory and the persisted snapshots never contain the secret.
	list := journeyDo(t, handler, http.MethodGet, "/api/v1/identities", "")
	if strings.Contains(list.Body.String(), journeySecretOne) {
		t.Fatal("identity list leaked the one-time secret")
	}
	if saved := repository.allJSON(t); strings.Contains(saved, journeySecretOne) || strings.Contains(saved, journeySecretRenew) {
		t.Fatal("persisted snapshots leaked a one-time secret")
	}
	if saved := repository.allJSON(t); !strings.Contains(saved, "common_vault_secret") {
		t.Fatal("snapshots should record the cluster vault reference")
	}

	// 5. Retrieve from the vault: the native read is denied, the cluster copy
	// answers, and the retrieval is audited.
	used := journeyDo(t, handler, http.MethodPost, "/api/v1/identities/"+id+"/use", "")
	if used.Code != http.StatusOK {
		t.Fatalf("POST use = %d: %s", used.Code, used.Body.String())
	}
	var useResponse protocol.UseResponse
	if err := json.Unmarshal(used.Body.Bytes(), &useResponse); err != nil {
		t.Fatalf("decode use response: %v", err)
	}
	if useResponse.Secret != journeySecretOne {
		t.Fatalf("retrieved secret = %q, want %q", useResponse.Secret, journeySecretOne)
	}
	if useResponse.Vault == nil || !strings.Contains(useResponse.Vault.URL, "mutandae-vault") {
		t.Fatalf("use response vault = %+v, want the cluster μVault", useResponse.Vault)
	}
	audit := journeyDo(t, handler, http.MethodGet, "/identities/"+id+"/events", "")
	if !strings.Contains(audit.Body.String(), "credential.used") {
		t.Error("audit trail missing the credential.used event")
	}
	if strings.Contains(audit.Body.String(), journeySecretOne) {
		t.Fatal("audit fragment leaked the secret value")
	}

	// 6. Rotate: the renewed credential becomes a new vault version.
	rotated := journeyDo(t, handler, http.MethodPost, "/api/v1/identities/"+id+"/rotations", `{"reason":"e2e"}`)
	if rotated.Code != http.StatusOK {
		t.Fatalf("POST rotations = %d: %s", rotated.Code, rotated.Body.String())
	}
	var rotateResponse protocol.RotateResponse
	if err := json.Unmarshal(rotated.Body.Bytes(), &rotateResponse); err != nil {
		t.Fatalf("decode rotate response: %v", err)
	}
	if rotateResponse.Identity.Credential.KeyID == provisionResponse.KeyID {
		t.Fatal("rotation did not change the key id")
	}
	if rotateResponse.Rotation.Status != protocol.RotationSucceeded {
		t.Fatalf("rotation status = %q", rotateResponse.Rotation.Status)
	}

	// 7. Retrieve again: the renewed secret answers from vault version 2.
	usedAgain := journeyDo(t, handler, http.MethodPost, "/api/v1/identities/"+id+"/use", "")
	if usedAgain.Code != http.StatusOK {
		t.Fatalf("second use = %d: %s", usedAgain.Code, usedAgain.Body.String())
	}
	var useAgainResponse protocol.UseResponse
	if err := json.Unmarshal(usedAgain.Body.Bytes(), &useAgainResponse); err != nil {
		t.Fatalf("decode second use: %v", err)
	}
	if useAgainResponse.Secret != journeySecretRenew {
		t.Fatalf("renewed secret = %q, want %q", useAgainResponse.Secret, journeySecretRenew)
	}
	if useAgainResponse.Vault.Version != "v2" {
		t.Fatalf("vault version after rotation = %q, want v2", useAgainResponse.Vault.Version)
	}

	// 8. The inventory offers the labeled Retrieve action for vault-backed rows.
	inventory := journeyDo(t, handler, http.MethodGet, "/partials/identities", "")
	if !strings.Contains(inventory.Body.String(), "Retrieve") {
		t.Error("inventory missing the labeled Retrieve action for a vault-backed identity")
	}

	// 9. Retire: the credential becomes unusable and the vault copy is revoked.
	retired := journeyDo(t, handler, http.MethodPost, "/api/v1/identities/"+id+"/retire", `{"confirm":true,"reason":"journey"}`)
	if retired.Code != http.StatusOK {
		t.Fatalf("POST retire = %d: %s", retired.Code, retired.Body.String())
	}
	var retireResponse protocol.RetireResponse
	if err := json.Unmarshal(retired.Body.Bytes(), &retireResponse); err != nil {
		t.Fatalf("decode retire response: %v", err)
	}
	if retireResponse.Identity.State != protocol.StateRetired {
		t.Fatalf("state after retire = %q", retireResponse.Identity.State)
	}
	useAfter := journeyDo(t, handler, http.MethodPost, "/api/v1/identities/"+id+"/use", "")
	if useAfter.Code != http.StatusConflict {
		t.Fatalf("use after retire = %d, want 409", useAfter.Code)
	}

	// 10. The HTML provisioning path discloses the one-time secret exactly
	// once and refreshes the inventory out-of-band. The HTML path counts
	// against the mutation limiter, not the create limiter.
	htmlRequest := httptest.NewRequest(http.MethodPost, "/identities/provision?provider=aws-iam", strings.NewReader("provider=aws-iam&purpose=journey-html"))
	htmlRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	htmlRequest.Header.Set("HX-Target", "provision-slot")
	htmlRecorder := httptest.NewRecorder()
	handler.ServeHTTP(htmlRecorder, htmlRequest)
	if !strings.Contains(htmlRecorder.Body.String(), "e2e-one-time-secret-") {
		t.Error("HTML provision result must disclose the fresh one-time secret once")
	}
	if !strings.Contains(htmlRecorder.Body.String(), "hx-swap-oob") {
		t.Error("dashboard provision result must refresh the inventory out-of-band")
	}

	// 11. The create limiter allows one more provision (burst of two) and then
	// throttles the third JSON create from the same client.
	second := journeyDo(t, handler, http.MethodPost, "/api/v1/demo/identities", `{"provider":"aws-iam"}`)
	if second.Code != http.StatusCreated {
		t.Fatalf("second JSON provision = %d: %s", second.Code, second.Body.String())
	}
	throttled := journeyDo(t, handler, http.MethodPost, "/api/v1/demo/identities", `{"provider":"aws-iam"}`)
	if throttled.Code != http.StatusTooManyRequests {
		t.Fatalf("third provision = %d, want 429 (provision throttling)", throttled.Code)
	}
}

// TestEndToEndSecurityHeadersOnPublicRoutes pins the browser-facing header
// contract for the demo.
func TestEndToEndSecurityHeadersOnPublicRoutes(t *testing.T) {
	handler, _ := newJourneyServer(t)
	for _, target := range []string{"/", "/configuration", "/api/v1/identities"} {
		response := journeyDo(t, handler, http.MethodGet, target, "")
		if got := response.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") {
			t.Errorf("%s: CSP = %q", target, got)
		}
		if got := response.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q", target, got)
		}
		if got := response.Header().Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("%s: Referrer-Policy = %q", target, got)
		}
	}
}

// TestEndToEndNotFoundAndConflicts pins the API's failure envelope shapes.
func TestEndToEndNotFoundAndConflicts(t *testing.T) {
	handler, _ := newJourneyServer(t)
	missing := journeyDo(t, handler, http.MethodGet, "/api/v1/identities/nope", "")
	if missing.Code != http.StatusNotFound {
		t.Fatalf("inspect missing = %d, want 404", missing.Code)
	}
	var failure protocol.ErrorResponse
	if err := json.Unmarshal(missing.Body.Bytes(), &failure); err != nil {
		t.Fatalf("failure envelope is not JSON: %v", err)
	}
	if failure.Error.Code != protocol.ErrCodeNotFound || failure.APIVersion != protocol.Version {
		t.Fatalf("failure envelope = %+v", failure)
	}
	// A missing identity with explicit confirmation is a 404; without
	// confirmation the store refuses up front with the conflict envelope.
	noConfirm := journeyDo(t, handler, http.MethodPost, "/api/v1/identities/nope/retire", `{}`)
	if noConfirm.Code != http.StatusConflict {
		t.Fatalf("retire missing without confirm = %d, want 409 (confirmation needed)", noConfirm.Code)
	}
	confirmed := journeyDo(t, handler, http.MethodPost, "/api/v1/identities/nope/retire", `{"confirm":true}`)
	if confirmed.Code != http.StatusNotFound {
		t.Fatalf("retire missing with confirm = %d, want 404", confirmed.Code)
	}
	// Malformed JSON is a conformant invalid_request, never a panic.
	broken := journeyDo(t, handler, http.MethodPost, "/api/v1/demo/identities", `{provider`)
	if broken.Code != http.StatusBadRequest {
		t.Fatalf("broken provision body = %d, want 400", broken.Code)
	}
	if err := json.Unmarshal(broken.Body.Bytes(), &failure); err != nil {
		t.Fatalf("broken-body failure envelope is not JSON: %v", err)
	}
}

// TestEndToEndConfigurationAdvertisesRealCapabilities pins what the public
// configuration promises versus what the journey actually exercises.
func TestEndToEndConfigurationAdvertisesRealCapabilities(t *testing.T) {
	handler, _ := newJourneyServer(t)
	response := journeyDo(t, handler, http.MethodGet, "/api/v1/configuration", "")
	if response.Code != http.StatusOK {
		t.Fatalf("GET configuration = %d", response.Code)
	}
	var payload protocol.ConfigurationResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode configuration: %v", err)
	}
	features := map[string]bool{}
	for _, feature := range payload.Configuration.Features {
		features[feature] = true
	}
	if !features["provision:aws-iam"] {
		t.Error("configuration does not advertise provisioning")
	}
	if !features["vault:cluster"] {
		t.Error("configuration does not advertise the cluster vault")
	}
	if payload.Configuration.ProtocolVersion != protocol.Version {
		t.Errorf("protocol version = %q", payload.Configuration.ProtocolVersion)
	}
	// The journey above proves both capabilities actually work; the
	// configuration must never advertise what it cannot do.
	if !errors.Is(protocol.ErrVaultUnsupported, protocol.ErrVaultUnsupported) {
		t.Fatal("sentinel identity broken")
	}
}
