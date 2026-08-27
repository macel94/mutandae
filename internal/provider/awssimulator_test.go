package provider

import (
	"context"
	"testing"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// awsSimTime fixes the simulated provider clock. It is intentionally named
// distinctly from the azure test's simTime helper to avoid a package-level
// collision.
func awsSimTime() time.Time {
	return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
}

func TestAWSSimulatorKind(t *testing.T) {
	if got := NewAWSSimulator("123456789012", "us-east-1", awsSimTime()).Kind(); got != "aws-iam" {
		t.Fatalf("Kind() = %q, want aws-iam", got)
	}
}

func TestAWSSimulatorDiscoversSeededIdentities(t *testing.T) {
	sim := NewAWSSimulator("123456789012", "us-east-1", awsSimTime())
	identities, err := sim.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(identities) != 3 {
		t.Fatalf("Discover() returned %d, want 3 seeded IAM users", len(identities))
	}
	for _, identity := range identities {
		// The provider view has no governance ID until the control plane adopts
		// it, so mirror that assignment before validating provider fields.
		identity.ID = identity.Name
		if err := protocol.ValidateIdentity(&identity); err != nil {
			t.Errorf("discovered identity %q is non-conformant: %v", identity.Name, err)
		}
		if identity.Provider.Provider != "aws-iam" {
			t.Errorf("provider for %q = %q, want aws-iam", identity.Name, identity.Provider.Provider)
		}
		if identity.Provider.AccountID != "123456789012" {
			t.Errorf("account_id for %q = %q, want 123456789012", identity.Name, identity.Provider.AccountID)
		}
		if identity.Provider.Region != "us-east-1" {
			t.Errorf("region for %q = %q, want us-east-1", identity.Name, identity.Provider.Region)
		}
		if identity.Provider.ProviderID != identity.Name {
			t.Errorf("provider_id for %q = %q, want the IAM user name", identity.Name, identity.Provider.ProviderID)
		}
		if identity.Credential.Kind != "access_key" {
			t.Errorf("credential kind for %q = %q, want access_key", identity.Name, identity.Credential.Kind)
		}
		if identity.Credential.Delivery != "secret-manager" {
			t.Errorf("credential delivery for %q = %q, want secret-manager", identity.Name, identity.Credential.Delivery)
		}
		if identity.Credential.Location != "iam://123456789012/user/"+identity.Name {
			t.Errorf("credential location for %q = %q", identity.Name, identity.Credential.Location)
		}
		if identity.Health != protocol.HealthHealthy && identity.Health != protocol.HealthAttention {
			t.Errorf("health for %q = %q", identity.Name, identity.Health)
		}
		if _, err := protocol.ParseISO8601Duration(identity.Policy.RenewalPeriod); err != nil {
			t.Errorf("policy for %q = %q is not ISO-8601", identity.Name, identity.Policy.RenewalPeriod)
		}
	}
}

func TestAWSSimulatorRotateReplacesCredentialEvidence(t *testing.T) {
	sim := NewAWSSimulator("123456789012", "us-east-1", awsSimTime())
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
		t.Fatalf("rotation did not replace the access key id")
	}
	if after.Credential.Fingerprint == before.Credential.Fingerprint {
		t.Fatalf("rotation did not replace the credential fingerprint")
	}
	if !after.LastRotatedAt.After(before.LastRotatedAt) {
		t.Fatalf("rotate did not advance the last-rotated time")
	}
	if !after.ExpiresAt.After(before.ExpiresAt) {
		t.Fatalf("rotate did not extend expiry")
	}
	if after.Health != protocol.HealthHealthy {
		t.Fatalf("health after rotate = %q, want healthy", after.Health)
	}
}

func TestAWSSimulatorRetireDisablesAndHides(t *testing.T) {
	sim := NewAWSSimulator("123456789012", "us-east-1", awsSimTime())
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
	// Disabled IAM users are not (re)discovered.
	identities, err := sim.Discover(context.Background())
	if err != nil {
		t.Fatalf("second Discover() error = %v", err)
	}
	if len(identities) != 2 {
		t.Fatalf("after retirement Discover() returned %d, want 2", len(identities))
	}
}

func TestAWSSimulatorRotateRejectsUnknownOrDisabled(t *testing.T) {
	sim := NewAWSSimulator("123456789012", "us-east-1", awsSimTime())
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
		t.Fatal("Rotate accepted a retired IAM user")
	}
}
