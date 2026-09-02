package provider

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestAWSDemoOnlyDiscoverFiltersAndRefusesNonDemo asserts the live-demo safety
// property: with DemoOnly enabled the adapter lists only mutandae-demo-*
// identities and refuses to rotate/retire anything else, even when the caller
// fabricates an identity object pointing at a productive user.
func TestAWSDemoOnlyDiscoverFiltersAndRefusesNonDemo(t *testing.T) {
	fixed := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	iam := newFakeIAM(t)
	iam.seed("mutandae-demo-web", fixed.Add(-10*24*time.Hour), "demo-secret")
	iam.seed("ci-deployer", fixed.Add(-40*24*time.Hour), "prod-secret")
	adapter, server := newAWSAdapterForTest(t, iam, fixed)
	defer server.Close()
	adapter.demoOnly = true

	identities, err := adapter.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(identities) != 1 {
		t.Fatalf("demo-only Discover returned %d identities, want 1: %+v", len(identities), identities)
	}
	if !strings.HasPrefix(identities[0].Name, "mutandae-demo-") {
		t.Fatalf("demo-only Discover leaked non-demo identity %q", identities[0].Name)
	}

	// A fabricated rotation targeting a productive user must be refused.
	if _, err := adapter.Rotate(context.Background(), identities[0]); err != nil {
		t.Fatalf("rotating a demo identity should work: %v", err)
	}
	prod := identities[0]
	prod.Name = "ci-deployer"
	prod.Provider.ProviderID = "ci-deployer"
	if _, err := adapter.Rotate(context.Background(), prod); err == nil {
		t.Fatal("demo-only adapter rotated a non-demo identity")
	}
	if _, err := adapter.Retire(context.Background(), prod); err == nil {
		t.Fatal("demo-only adapter retired a non-demo identity")
	}
}
