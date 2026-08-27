package provider

import (
	"context"
	"testing"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

func gcpSimTime() time.Time {
	return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
}

func TestGCPSimulatorKind(t *testing.T) {
	if got := NewGCPSimulator("proj-1", "us-central1", gcpSimTime()).Kind(); got != "gcp-iam" {
		t.Fatalf("Kind() = %q, want gcp-iam", got)
	}
}

func TestGCPSimulatorDiscoversSeededIdentities(t *testing.T) {
	sim := NewGCPSimulator("proj-1", "us-central1", gcpSimTime())
	identities, err := sim.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(identities) != 3 {
		t.Fatalf("Discover() returned %d, want 3 seeded service accounts", len(identities))
	}
	for _, identity := range identities {
		// The provider view has no governance ID until the control plane adopts
		// it, so assign it before validating provider fields.
		identity.ID = identity.Name
		if err := protocol.ValidateIdentity(&identity); err != nil {
			t.Errorf("discovered identity %q is non-conformant: %v", identity.Name, err)
		}
		if identity.Provider.Provider != "gcp-iam" {
			t.Errorf("binding provider for %q = %q, want gcp-iam", identity.Name, identity.Provider.Provider)
		}
		if identity.Provider.ProjectID != "proj-1" {
			t.Errorf("project_id for %q = %q, want proj-1", identity.Name, identity.Provider.ProjectID)
		}
		if identity.Provider.Region != "us-central1" {
			t.Errorf("region for %q = %q, want us-central1", identity.Name, identity.Provider.Region)
		}
		if identity.Credential.Kind != "service_account_key" {
			t.Errorf("credential kind for %q = %q, want service_account_key", identity.Name, identity.Credential.Kind)
		}
		if identity.Credential.Delivery != "secret-manager" {
			t.Errorf("credential delivery for %q = %q, want secret-manager", identity.Name, identity.Credential.Delivery)
		}
		if identity.Health != protocol.HealthHealthy && identity.Health != protocol.HealthAttention {
			t.Errorf("health for %q = %q", identity.Name, identity.Health)
		}
		if _, err := protocol.ParseISO8601Duration(identity.Policy.RenewalPeriod); err != nil {
			t.Errorf("policy for %q = %q is not ISO-8601", identity.Name, identity.Policy.RenewalPeriod)
		}
	}
}

func TestGCPSimulatorRotateReplacesKeyEvidence(t *testing.T) {
	sim := NewGCPSimulator("proj-1", "us-central1", gcpSimTime())
	identity, err := sim.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	before := identity[0]
	after, err := sim.Rotate(context.Background(), before)
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if after.Credential.KeyID == before.Credential.KeyID {
		t.Fatalf("rotation did not replace the credential key id")
	}
	if after.Credential.Fingerprint == before.Credential.Fingerprint {
		t.Fatalf("rotation did not replace the credential fingerprint")
	}
	if after.LastRotatedAt.Before(before.LastRotatedAt) {
		t.Fatalf("rotation did not advance the last-rotated time")
	}
	if !after.ExpiresAt.After(before.ExpiresAt) {
		t.Fatalf("rotation did not extend expiry")
	}
	if after.Health != protocol.HealthHealthy {
		t.Fatalf("health after rotation = %q, want healthy", after.Health)
	}
}

func TestGCPSimulatorRetireDisablesAndHides(t *testing.T) {
	sim := NewGCPSimulator("proj-1", "us-central1", gcpSimTime())
	identity, err := sim.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	retired, err := sim.Retire(context.Background(), identity[0])
	if err != nil {
		t.Fatalf("Retire() error = %v", err)
	}
	if retired.State != protocol.StateRetired {
		t.Fatalf("state = %q, want retired", retired.State)
	}
	// Disabled service accounts are not (re)discovered.
	identities, err := sim.Discover(context.Background())
	if err != nil {
		t.Fatalf("second Discover() error = %v", err)
	}
	if len(identities) != 2 {
		t.Fatalf("after retirement Discover() returned %d, want 2", len(identities))
	}
}

func TestGCPSimulatorRotateRejectsUnknownOrDisabled(t *testing.T) {
	sim := NewGCPSimulator("proj-1", "us-central1", gcpSimTime())
	unknown := protocol.MachineIdentity{Provider: protocol.ProviderBinding{ProviderID: "nope"}}
	if _, err := sim.Rotate(context.Background(), unknown); err == nil {
		t.Fatal("Rotate accepted an unknown provider id")
	}

	discovered, _ := sim.Discover(context.Background())
	disabled, err := sim.Retire(context.Background(), discovered[0])
	if err != nil {
		t.Fatalf("Retire() error = %v", err)
	}
	if _, err := sim.Rotate(context.Background(), disabled); err == nil {
		t.Fatal("Rotate accepted a retired service account")
	}
}
