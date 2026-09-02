package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

func now() time.Time {
	return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
}

func discovered(name string) protocol.MachineIdentity {
	return protocol.MachineIdentity{
		Name:      name,
		Provider:  protocol.ProviderBinding{Provider: "azure-entra", ProviderID: name + "-objid", TenantID: "tenant-1"},
		Ownership: protocol.Ownership{Team: "Payments", Service: "authz", Purpose: "authorization", Criticality: "high"},
		Policy:    protocol.LifecyclePolicy{RenewalPeriod: "P90D", ApprovalRequired: false},
		State:     protocol.StateActive, Health: protocol.HealthHealthy,
		ExpiresAt: now().Add(30 * 24 * time.Hour),
	}
}

type fakeAdapter struct {
	discoveries  []protocol.MachineIdentity
	failDiscover error
	failRotate   error
	failRetire   error
	rotations    int
	retired      []string
}

func (f *fakeAdapter) Kind() string { return "azure-entra" }
func (f *fakeAdapter) Discover(context.Context) ([]protocol.MachineIdentity, error) {
	if f.failDiscover != nil {
		return nil, f.failDiscover
	}
	return append([]protocol.MachineIdentity(nil), f.discoveries...), nil
}
func (f *fakeAdapter) Rotate(_ context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	f.rotations++
	if f.failRotate != nil {
		return protocol.MachineIdentity{}, f.failRotate
	}
	identity.Credential.KeyID = identity.Name + "-new-key"
	identity.Credential.Fingerprint = "sha256:new"
	return identity, nil
}
func (f *fakeAdapter) Retire(_ context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	if f.failRetire != nil {
		return protocol.MachineIdentity{}, f.failRetire
	}
	f.retired = append(f.retired, identity.ID)
	identity.State = protocol.StateRetired
	identity.Provider.ProviderID = identity.Provider.ProviderID + "-disabled"
	return identity, nil
}

func testStore(t *testing.T, adapter Adapter) *Store {
	t.Helper()
	store, err := NewStore(context.Background(), now(), adapter)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	return store
}

func TestNewStoreRequiresAdapter(t *testing.T) {
	if _, err := NewStore(context.Background(), now(), nil); !errors.Is(err, ErrAdapterRequired) {
		t.Fatalf("NewStore(nil) error = %v, want ErrAdapterRequired", err)
	}
}

func TestNewStoreBootsFromProviderDiscovery(t *testing.T) {
	store := testStore(t, &fakeAdapter{
		discoveries: []protocol.MachineIdentity{discovered("payments-api"), discovered("data-pipeline")},
	})
	identities := store.List()
	if len(identities) != 2 {
		t.Fatalf("List() returned %d, want 2", len(identities))
	}
	// Governance IDs, state, and provenance are applied by the control plane to
	// every discovered identity (List is ordered by expiry, then name).
	for _, identity := range identities {
		if identity.ID == "" || identity.State != protocol.StateActive {
			t.Fatalf("identity = %+v, want a governance id and active state", identity)
		}
	}
	events, ok := store.Events("payments-api")
	if !ok || len(events) < 2 {
		t.Fatalf("expected discovery+registration events, got %d", len(events))
	}
	wantTypes := []protocol.EventType{protocol.EventIdentityRegistered, protocol.EventIdentityDiscovered}
	for i, want := range wantTypes {
		if events[i].Type != want {
			t.Errorf("event[%d].Type = %q, want %q", i, events[i].Type, want)
		}
	}
}

func TestNewStoreRejectsNonConformantDiscovery(t *testing.T) {
	bad := discovered("broken")
	bad.Provider.Provider = ""
	if _, err := NewStore(context.Background(), now(), &fakeAdapter{discoveries: []protocol.MachineIdentity{bad}}); err == nil {
		t.Fatal("NewStore accepted a non-conformant discovered identity")
	}
}

func TestTransitionUsesProtocolStateMachine(t *testing.T) {
	if err := Transition(protocol.StateActive, protocol.StateRenewing); err != nil {
		t.Fatalf("active->renewing should be valid: %v", err)
	}
	if err := Transition(protocol.StateRetired, protocol.StateActive); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("retired->active error = %v, want ErrInvalidTransition", err)
	}
}

func TestRotateExtendsExpiryAndCorrelatesRun(t *testing.T) {
	adapter := &fakeAdapter{discoveries: []protocol.MachineIdentity{discovered("payments-api")}}
	store := testStore(t, adapter)

	before, ok := store.Get("payments-api")
	if !ok {
		t.Fatal("payments-api was not discovered")
	}
	resp, err := store.Rotate(context.Background(), protocol.RotateRequest{ID: "payments-api", RequestedBy: "tester"}, now())
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if resp.Rotation.Status != protocol.RotationSucceeded || resp.Rotation.Outcome != protocol.OutcomeSuccess {
		t.Fatalf("rotation = %+v, want succeeded", resp.Rotation)
	}
	identity := resp.Identity
	if identity.State != protocol.StateActive || identity.Health != protocol.HealthHealthy {
		t.Fatalf("state/health = %q/%q, want active/healthy", identity.State, identity.Health)
	}
	if !identity.ExpiresAt.After(before.ExpiresAt) {
		t.Fatalf("expiry = %v, want after previous %v", identity.ExpiresAt, before.ExpiresAt)
	}
	if identity.Credential.KeyID != "payments-api-new-key" {
		t.Fatalf("credential key id = %q, want evidence from adapter", identity.Credential.KeyID)
	}
	if adapter.rotations != 1 {
		t.Fatalf("adapter rotations = %d, want 1", adapter.rotations)
	}

	runs, ok := store.Runs("payments-api")
	if !ok || len(runs) != 1 || runs[0].Status != protocol.RotationSucceeded {
		t.Fatalf("runs = %#v, want a single succeeded run", runs)
	}

	events, _ := store.Events("payments-api")
	var hadStarted, hadCompleted bool
	var startedCorr, completedCorr string
	for _, e := range events {
		switch e.Type {
		case protocol.EventRotationStarted:
			hadStarted = true
			startedCorr = e.CorrelationID
		case protocol.EventRotationCompleted:
			hadCompleted = true
			completedCorr = e.CorrelationID
		default:
			continue // discovery/registration events are not rotation-scoped
		}
		if e.RunID != runs[0].ID {
			t.Errorf("event %q missing run correlation", e.Type)
		}
		if e.CorrelationID != runs[0].ID {
			t.Errorf("event %q correlation_id = %q, want run id %q", e.Type, e.CorrelationID, runs[0].ID)
		}
	}
	if !hadStarted || !hadCompleted {
		t.Fatalf("expected rotation.started and rotation.completed events, got %#v", events)
	}
	if startedCorr == "" || startedCorr != completedCorr {
		t.Errorf("rotation events do not share a correlation_id: started=%q completed=%q", startedCorr, completedCorr)
	}
}

func TestRotateFailureReturnsToActiveWithAttention(t *testing.T) {
	adapter := &fakeAdapter{
		discoveries: []protocol.MachineIdentity{discovered("payments-api")},
		failRotate:  errors.New("provider is down"),
	}
	store := testStore(t, adapter)
	_, err := store.Rotate(context.Background(), protocol.RotateRequest{ID: "payments-api"}, now())
	if !errors.Is(err, ErrProviderFailure) {
		t.Fatalf("Rotate() error = %v, want ErrProviderFailure", err)
	}
	identity, _ := store.Get("payments-api")
	if identity.State != protocol.StateActive || identity.Health != protocol.HealthAttention {
		t.Fatalf("state/health = %q/%q, want active/attention for retry", identity.State, identity.Health)
	}
	runs, _ := store.Runs("payments-api")
	if len(runs) != 1 || runs[0].Status != protocol.RotationFailed {
		t.Fatalf("runs = %#v, want failed run", runs)
	}
	events, _ := store.Events("payments-api")
	var hadFailed bool
	for _, e := range events {
		if e.Type == protocol.EventRotationFailed {
			hadFailed = true
		}
	}
	if !hadFailed {
		t.Fatalf("expected rotation.failed event")
	}
}

func TestRotateRejectsMissingAndRetiredAndNested(t *testing.T) {
	store := testStore(t, &fakeAdapter{discoveries: []protocol.MachineIdentity{discovered("payments-api")}})
	if _, err := store.Rotate(context.Background(), protocol.RotateRequest{ID: "missing"}, now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing error = %v, want ErrNotFound", err)
	}

	retiredStore := testStore(t, &fakeAdapter{discoveries: []protocol.MachineIdentity{discovered("old")}})
	if _, err := retiredStore.Retire(context.Background(), protocol.RetireRequest{ID: "old", Confirm: true}, now()); err != nil {
		t.Fatalf("Retire() error = %v", err)
	}
	if _, err := retiredStore.Rotate(context.Background(), protocol.RotateRequest{ID: "old"}, now()); !errors.Is(err, ErrAlreadyRetired) {
		t.Fatalf("retired rotate error = %v, want ErrAlreadyRetired", err)
	}
}

func TestRetireRequiresConfirmationAndDecommissions(t *testing.T) {
	adapter := &fakeAdapter{discoveries: []protocol.MachineIdentity{discovered("payments-api")}}
	store := testStore(t, adapter)

	if _, err := store.Retire(context.Background(), protocol.RetireRequest{ID: "payments-api"}, now()); !errors.Is(err, ErrConfirmationNeeded) {
		t.Fatalf("without confirm error = %v, want ErrConfirmationNeeded", err)
	}
	resp, err := store.Retire(context.Background(), protocol.RetireRequest{ID: "payments-api", Confirm: true, Reason: "eol"}, now())
	if err != nil {
		t.Fatalf("Retire() error = %v", err)
	}
	if resp.Identity.State != protocol.StateRetired {
		t.Fatalf("state = %q, want retired", resp.Identity.State)
	}
	if len(adapter.retired) != 1 || adapter.retired[0] != "payments-api" {
		t.Fatalf("adapter retired = %v, want [payments-api]", adapter.retired)
	}
	events, _ := store.Events("payments-api")
	if events[0].Type != protocol.EventIdentityRetired {
		t.Fatalf("latest event = %q, want identity.retired", events[0].Type)
	}
}

func TestRegisterValidatesAndPersists(t *testing.T) {
	store := testStore(t, &fakeAdapter{})

	req := protocol.RegisterRequest{
		Name: "new-service", Environment: "production",
		Provider:    protocol.ProviderBinding{Provider: "azure-entra", ProviderID: "new-objid", TenantID: "t1"},
		Ownership:   protocol.Ownership{Team: "Platform", Service: "svc", Purpose: "purpose", Criticality: "high"},
		Policy:      protocol.LifecyclePolicy{RenewalPeriod: "P45D"},
		RequestedBy: "demo-operator",
	}
	resp, err := store.Register(context.Background(), req, now())
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if resp.Identity.ExpiresAt.Sub(now()) != 45*24*time.Hour {
		t.Fatalf("expiry offset = %v, want 45d", resp.Identity.ExpiresAt.Sub(now()))
	}
	if !reflect.DeepEqual(resp.Events[0].Type, protocol.EventIdentityRegistered) {
		t.Fatalf("event type = %v, want registered", resp.Events[0].Type)
	}

	// Duplicate and invalid requests must be rejected.
	if _, err := store.Register(context.Background(), req, now()); err == nil {
		t.Fatal("duplicate register succeeded")
	}
	bad := req
	bad.Name = "second"
	bad.Policy.RenewalPeriod = "sometimes"
	if _, err := store.Register(context.Background(), bad, now()); !errors.Is(err, protocol.ErrConformance) {
		t.Fatalf("invalid policy error = %v, want ErrConformance", err)
	}
}

func TestErrorCodeMapping(t *testing.T) {
	cases := map[error]protocol.ErrorCode{
		ErrNotFound:           protocol.ErrCodeNotFound,
		ErrInvalidTransition:  protocol.ErrCodeInvalidTransition,
		ErrAlreadyRetired:     protocol.ErrCodeAlreadyRetired,
		ErrRotationInProgress: protocol.ErrCodeRotationInProgress,
		ErrProviderFailure:    protocol.ErrCodeProviderFailure,
		ErrConformance:        protocol.ErrCodeConformanceFailure,
		errors.New("boom"):    protocol.ErrCodeInternal,
	}
	for err, want := range cases {
		if got := ErrorCode(err); got != want {
			t.Errorf("ErrorCode(%v) = %q, want %q", err, got, want)
		}
	}
}

// provisioningAdapter wraps fakeAdapter with the Provisioner capability so the
// store can provision through it and we can assert the one-time secret is
// never persisted.
type provisioningAdapter struct {
	*fakeAdapter
	mu           sync.Mutex
	createdNames []string
}

func (p *provisioningAdapter) Create(_ context.Context, provider, name string) (protocol.ProvisionResponse, error) {
	p.mu.Lock()
	p.createdNames = append(p.createdNames, name)
	p.mu.Unlock()
	return protocol.ProvisionResponse{
		APIVersion: protocol.Version,
		Identity: protocol.MachineIdentity{
			ID:          "mutandae-demo-ab12",
			Name:        "mutandae-demo-ab12",
			DisplayName: "mutandae-demo-ab12",
			Provider:    protocol.ProviderBinding{Provider: provider, ProviderID: "prov1"},
			Ownership:   protocol.Ownership{Team: "Demo", Service: "mutandae-demo-ab12", Purpose: "Public demo identity with zero permissions"},
			Policy:      protocol.LifecyclePolicy{RenewalPeriod: "P1D"},
			Credential:  protocol.CredentialReference{Kind: "access_key", KeyID: "key-1", Location: "iam://account/user/mutandae-demo-ab12"},
		},
		OneTimeSecret: "top-secret",
		KeyID:         "key-1",
		Instructions:  "use immediately",
	}, nil
}

func TestStoreProvisionAdoptsAndNeverPersistsSecret(t *testing.T) {
	p := &provisioningAdapter{fakeAdapter: &fakeAdapter{}}
	store, err := NewStore(context.Background(), now(), p)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	resp, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam", Purpose: "demo"}, now())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if resp.OneTimeSecret != "top-secret" {
		t.Fatalf("response secret = %q", resp.OneTimeSecret)
	}
	stored := store.List()
	if len(stored) != 1 {
		t.Fatalf("stored identities = %d, want 1", len(stored))
	}
	if stored[0].Name != "mutandae-demo-ab12" || stored[0].State != protocol.StateActive {
		t.Fatalf("unexpected stored identity: %+v", stored[0])
	}
	// Ensure the credential reference and events never carry the secret.
	if strings.Contains(fmt.Sprint(stored[0]), "top-secret") {
		t.Fatal("one-time secret persisted into the stored identity")
	}
	events, _ := store.Events(stored[0].ID)
	if strings.Contains(fmt.Sprint(events), "top-secret") {
		t.Fatal("one-time secret leaked into a lifecycle event")
	}
	// A missing provider is rejected.
	if _, err := store.Provision(context.Background(), protocol.ProvisionRequest{}, now()); err == nil {
		t.Fatal("Provision without provider should error")
	}
}

func TestStoreProvisionUnsupportedAdapter(t *testing.T) {
	adapter := &fakeAdapter{}
	store, err := NewStore(context.Background(), now(), adapter)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if _, err := store.Provision(context.Background(), protocol.ProvisionRequest{Provider: "aws-iam"}, now()); err == nil {
		t.Fatal("Provision on a non-provisioning adapter should error")
	}
}
