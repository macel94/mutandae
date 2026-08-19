package provider

import (
	"context"
	"testing"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

func simTime() time.Time {
	return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
}

func TestSimulatorKind(t *testing.T) {
	if got := NewSimulator("t1", simTime()).Kind(); got != "azure-entra" {
		t.Fatalf("Kind() = %q, want azure-entra", got)
	}
}

func TestSimulatorDiscoversSeededIdentities(t *testing.T) {
	sim := NewSimulator("t1", simTime())
	identities, err := sim.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(identities) != 4 {
		t.Fatalf("Discover() returned %d, want 4 seeded registrations", len(identities))
	}
	for _, identity := range identities {
		// The provider view has no governance ID until the control plane adopts
		// it, so mirror that assignment before validating provider fields.
		identity.ID = identity.Name
		if err := protocol.ValidateIdentity(&identity); err != nil {
			t.Errorf("discovered identity %q is non-conformant: %v", identity.Name, err)
		}
		if identity.Provider.Provider != "azure-entra" || identity.Provider.TenantID != "t1" {
			t.Errorf("binding for %q = %+v, want azure-entra in tenant t1", identity.Name, identity.Provider)
		}
		if identity.Health != protocol.HealthHealthy && identity.Health != protocol.HealthAttention {
			t.Errorf("health for %q = %q", identity.Name, identity.Health)
		}
		if _, err := protocol.ParseISO8601Duration(identity.Policy.RenewalPeriod); err != nil {
			t.Errorf("policy for %q = %q is not ISO-8601", identity.Name, identity.Policy.RenewalPeriod)
		}
	}
}

func TestSimulatorRotateReplacesCredentialEvidence(t *testing.T) {
	sim := NewSimulator("t1", simTime())
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
}

func TestSimulatorRetireDisablesAndHides(t *testing.T) {
	sim := NewSimulator("t1", simTime())
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
	// Disabled registrations are not (re)discovered.
	identities, err := sim.Discover(context.Background())
	if err != nil {
		t.Fatalf("second Discover() error = %v", err)
	}
	if len(identities) != 3 {
		t.Fatalf("after retirement Discover() returned %d, want 3", len(identities))
	}
}

func TestSimulatorRotateRejectsUnknownOrDisabled(t *testing.T) {
	sim := NewSimulator("t1", simTime())
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
		t.Fatal("Rotate accepted a retired registration")
	}
}
