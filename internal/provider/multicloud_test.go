package provider

import (
	"context"
	"testing"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// stubAdapter is a minimal CloudAdapter used to exercise the composite's
// fan-out and routing without depending on a real simulator.
type stubAdapter struct {
	kind       string
	identities []protocol.MachineIdentity
	rotated    int
	retired    int
}

func (s *stubAdapter) Kind() string { return s.kind }
func (s *stubAdapter) Discover(context.Context) ([]protocol.MachineIdentity, error) {
	return s.identities, nil
}
func (s *stubAdapter) Rotate(_ context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	s.rotated++
	return identity, nil
}
func (s *stubAdapter) Retire(_ context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	s.retired++
	identity.State = protocol.StateRetired
	return identity, nil
}

func identityOf(kind, id string) protocol.MachineIdentity {
	return protocol.MachineIdentity{
		Name:     id,
		Provider: protocol.ProviderBinding{Provider: kind, ProviderID: id},
	}
}

func TestNewMultiProviderRequiresAdapter(t *testing.T) {
	if _, err := NewMultiProvider(); err == nil {
		t.Fatal("NewMultiProvider with no adapters did not error")
	}
	if _, err := NewMultiProvider(nil, &stubAdapter{kind: "aws-iam"}); err == nil {
		t.Fatal("NewMultiProvider accepted a nil adapter")
	}
	if _, err := NewMultiProvider(&stubAdapter{kind: "aws-iam"}, &stubAdapter{kind: "aws-iam"}); err == nil {
		t.Fatal("NewMultiProvider accepted duplicate provider kinds")
	}
	if _, err := NewMultiProvider(&stubAdapter{kind: "  "}); err == nil {
		t.Fatal("NewMultiProvider accepted an empty provider kind")
	}
}

func TestMultiProviderKindAndKinds(t *testing.T) {
	m, err := NewMultiProvider(&stubAdapter{kind: "gcp-iam"}, &stubAdapter{kind: "azure-entra"}, &stubAdapter{kind: "aws-iam"})
	if err != nil {
		t.Fatalf("NewMultiProvider error = %v", err)
	}
	if m.Kind() != "multi-cloud" {
		t.Fatalf("Kind() = %q", m.Kind())
	}
	kinds := m.Kinds()
	want := []string{"aws-iam", "azure-entra", "gcp-iam"}
	if len(kinds) != 3 {
		t.Fatalf("Kinds() = %v", kinds)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("Kinds() = %v, want %v", kinds, want)
		}
	}
}

func TestMultiCloudDiscoverAggregatesAndDedupes(t *testing.T) {
	aws := &stubAdapter{kind: "aws-iam", identities: []protocol.MachineIdentity{identityOf("aws-iam", "a1"), identityOf("aws-iam", "a1")}}
	gcp := &stubAdapter{kind: "gcp-iam", identities: []protocol.MachineIdentity{identityOf("gcp-iam", "g1")}}
	m, err := NewMultiProvider(aws, gcp)
	if err != nil {
		t.Fatalf("NewMultiProvider error = %v", err)
	}
	got, err := m.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Discover returned %d identities, want 2 (duplicate removed)", len(got))
	}
}

func TestMultiCloudRoutesRotation(t *testing.T) {
	aws := &stubAdapter{kind: "aws-iam", identities: []protocol.MachineIdentity{identityOf("aws-iam", "a1")}}
	m, _ := NewMultiProvider(aws)
	if _, err := m.Rotate(context.Background(), identityOf("aws-iam", "a1")); err != nil {
		t.Fatalf("Rotate error = %v", err)
	}
	if aws.rotated != 1 {
		t.Fatalf("aws adapter rotated = %d, want 1", aws.rotated)
	}
	if _, err := m.Rotate(context.Background(), identityOf("azure-entra", "x")); err == nil {
		t.Fatal("Rotate accepted an identity with no governing adapter")
	}
}

func TestMultiCloudRoutesRetire(t *testing.T) {
	aws := &stubAdapter{kind: "aws-iam"}
	m, _ := NewMultiProvider(aws)
	if _, err := m.Retire(context.Background(), identityOf("aws-iam", "a1")); err != nil {
		t.Fatalf("Retire error = %v", err)
	}
	if aws.retired != 1 {
		t.Fatalf("aws adapter retired = %d, want 1", aws.retired)
	}
	if _, err := m.Retire(context.Background(), identityOf("gcp-iam", "x")); err == nil {
		t.Fatal("Retire accepted an identity with no governing adapter")
	}
}
