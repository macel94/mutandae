package lifecycle

import (
	"context"
	"testing"
	"time"

	"github.com/mutandae/mutandae/internal/provider"
	"github.com/mutandae/mutandae/pkg/protocol"
)

func multiCloudAdapter(t *testing.T) *provider.MultiProvider {
	t.Helper()
	startedAt := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	adapter, err := provider.NewMultiProvider(
		provider.NewSimulator("test-tenant", startedAt),
		provider.NewAWSSimulator("123456789012", "us-east-1", startedAt),
		provider.NewGCPSimulator("test-project", "us-central1", startedAt),
	)
	if err != nil {
		t.Fatalf("NewMultiProvider() error = %v", err)
	}
	return adapter
}

func TestMultiCloudStoreAdoptsEveryProvider(t *testing.T) {
	startedAt := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	store, err := NewStore(context.Background(), startedAt, multiCloudAdapter(t))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	identities := store.List()
	if len(identities) != 10 {
		t.Fatalf("List() returned %d identities, want 10 (4 azure + 3 aws + 3 gcp)", len(identities))
	}
	seen := map[protocol.Health]int{}
	for _, identity := range identities {
		switch identity.Provider.Provider {
		case "azure-entra":
		case "aws-iam":
			if identity.Provider.AccountID != "123456789012" {
				t.Fatalf("aws-iam identity %q account_id = %q", identity.Name, identity.Provider.AccountID)
			}
		case "gcp-iam":
			if identity.Provider.ProjectID != "test-project" {
				t.Fatalf("gcp-iam identity %q project_id = %q", identity.Name, identity.Provider.ProjectID)
			}
		default:
			t.Fatalf("unexpected provider %q", identity.Provider.Provider)
		}
		seen[identity.Health]++
		if identity.State != protocol.StateActive {
			t.Fatalf("adopted identity %q state = %q, want active", identity.Name, identity.State)
		}
	}
	if seen[protocol.HealthHealthy] == 0 || seen[protocol.HealthAttention] == 0 {
		t.Fatalf("expected a mix of health states, got %+v", seen)
	}
}

func TestMultiCloudStoreRotatesThroughRoutingAdapter(t *testing.T) {
	startedAt := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	store, err := NewStore(context.Background(), startedAt, multiCloudAdapter(t))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	awsIdentity, ok := store.Get("orders-deployer")
	if !ok {
		t.Fatal("orders-deployer was not adopted")
	}
	resp, err := store.Rotate(context.Background(), protocol.RotateRequest{ID: awsIdentity.ID, RequestedBy: "multi-cloud-test"}, startedAt)
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if resp.Rotation.Status != protocol.RotationSucceeded {
		t.Fatalf("rotation status = %q, want succeeded", resp.Rotation.Status)
	}
	if resp.Identity.Provider.Provider != "aws-iam" {
		t.Fatalf("rotated identity provider = %q, want aws-iam", resp.Identity.Provider.Provider)
	}
	if resp.Identity.Credential.KeyID == awsIdentity.Credential.KeyID {
		t.Fatalf("rotation did not replace the AWS access key id")
	}
	if resp.Identity.Credential.Fingerprint == awsIdentity.Credential.Fingerprint {
		t.Fatalf("rotation did not replace the AWS credential fingerprint")
	}
	if resp.Identity.Health != protocol.HealthHealthy {
		t.Fatalf("rotated identity health = %q, want healthy", resp.Identity.Health)
	}
}

func TestMultiCloudStoreRetiresGCPIdentity(t *testing.T) {
	startedAt := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	store, err := NewStore(context.Background(), startedAt, multiCloudAdapter(t))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	gcpIdentity, ok := store.Get("inventory-broker")
	if !ok {
		t.Fatal("inventory-broker was not adopted")
	}
	retired, err := store.Retire(context.Background(), protocol.RetireRequest{ID: gcpIdentity.ID, RequestedBy: "multi-cloud-test", Confirm: true, Reason: "multi-cloud test"}, startedAt)
	if err != nil {
		t.Fatalf("Retire() error = %v", err)
	}
	if retired.Identity.State != protocol.StateRetired {
		t.Fatalf("retired identity state = %q, want retired", retired.Identity.State)
	}
	actions := []struct {
		name string
		do   func() (protocol.MachineIdentity, bool)
	}{
		{"inventory-broker", func() (protocol.MachineIdentity, bool) { return store.Get("inventory-broker") }},
		{"orders-deployer", func() (protocol.MachineIdentity, bool) { return store.Get("orders-deployer") }},
	}
	stateByID := map[string]protocol.State{}
	for _, action := range actions {
		identity, ok := action.do()
		if !ok {
			t.Fatalf("%s disappeared from the store", action.name)
		}
		stateByID[identity.Name] = identity.State
	}
	if stateByID["inventory-broker"] != protocol.StateRetired {
		t.Fatalf("inventory-broker state = %q, want retired", stateByID["inventory-broker"])
	}
	if stateByID["orders-deployer"] != protocol.StateActive {
		t.Fatalf("orders-deployer state = %q, want active", stateByID["orders-deployer"])
	}
}

func TestMultiCloudDiscoverSkipsRetired(t *testing.T) {
	adapter := multiCloudAdapter(t)
	_, err := adapter.Retire(context.Background(), protocol.MachineIdentity{Provider: protocol.ProviderBinding{Provider: "gcp-iam", ProviderID: "000000000000000000001"}})
	if err != nil {
		t.Fatalf("Retire() error = %v", err)
	}
	discovered, err := adapter.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(discovered) != 9 {
		t.Fatalf("Discover() returned %d identities, want 9 after retiring one GCP service account", len(discovered))
	}
	for _, identity := range discovered {
		if identity.Provider.Provider == "gcp-iam" && identity.Name == "inventory-broker" {
			t.Fatal("retired GCP service account was rediscovered")
		}
	}
}
