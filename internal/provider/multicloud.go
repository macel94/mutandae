package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// CloudAdapter is the provider-aware execution boundary the multi-cloud demo
// composes. It is structurally compatible with lifecycle.Adapter so the control
// plane treats the combined Demo provider exactly like a single provider.
//
// Implementations are responsible for a stable Kind, a provider-local view via
// Discover, and the Rotate/Retire mutations. The multi-cloud provider only
// fans discovery out and routes mutations by ProviderBinding.provider, so it
// never needs to know provider mechanics.
type CloudAdapter interface {
	Kind() string
	Discover(ctx context.Context) ([]protocol.MachineIdentity, error)
	Rotate(ctx context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error)
	Retire(ctx context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error)
}

// MultiProvider aggregates several provider adapters behind one lifecycle
// boundary so the demo can govern Azure/Entra ID, AWS IAM, and GCP IAM from a
// single control plane. It fans discovery out across every sub-adapter and
// routes Rotate/Retire to the adapter whose Kind matches the identity's
// provider binding.
type MultiProvider struct {
	adapters []CloudAdapter
}

// NewMultiProvider builds a composite adapter from the supplied sub-adapters.
// A nil or empty set is rejected so the control plane never discovers from an
// empty inventory.
func NewMultiProvider(adapters ...CloudAdapter) (*MultiProvider, error) {
	seen := make(map[string]CloudAdapter, len(adapters))
	for _, a := range adapters {
		if a == nil {
			return nil, fmt.Errorf("multi-cloud: a provider adapter is nil")
		}
		kind := strings.TrimSpace(a.Kind())
		if kind == "" {
			return nil, fmt.Errorf("multi-cloud: a provider adapter has an empty Kind")
		}
		if _, dup := seen[kind]; dup {
			return nil, fmt.Errorf("multi-cloud: duplicate provider kind %q", kind)
		}
		seen[kind] = a
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("multi-cloud: at least one provider adapter is required")
	}
	return &MultiProvider{adapters: adapters}, nil
}

// Kinds returns the sorted set of provider identifiers this composite governs.
func (m *MultiProvider) Kinds() []string {
	kinds := make([]string, 0, len(m.adapters))
	for _, a := range m.adapters {
		kinds = append(kinds, a.Kind())
	}
	sort.Strings(kinds)
	return kinds
}

// Kind is the composite's stable identifier. It is not a real cloud provider,
// so it is never placed into a ProviderBinding; identity bindings keep their
// originating provider kind.
func (m *MultiProvider) Kind() string { return "multi-cloud" }

// Discover aggregates the provider-local views of every sub-adapter, deduping
// by (provider, provider_id) so a misconfigured duplicate is not adopted twice.
func (m *MultiProvider) Discover(ctx context.Context) ([]protocol.MachineIdentity, error) {
	var identities []protocol.MachineIdentity
	seen := make(map[string]struct{})
	for _, a := range m.adapters {
		view, err := a.Discover(ctx)
		if err != nil {
			return nil, fmt.Errorf("%s: discover: %w", a.Kind(), err)
		}
		for _, identity := range view {
			key := identity.Provider.Provider + "/" + identity.Provider.ProviderID
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			identities = append(identities, identity)
		}
	}
	return identities, nil
}

// adapterFor routes an identity to the sub-adapter that governs its provider
// binding, reporting an error when no sub-adapter matches.
func (m *MultiProvider) adapterFor(providerKind string) (CloudAdapter, error) {
	for _, a := range m.adapters {
		if a.Kind() == strings.TrimSpace(providerKind) {
			return a, nil
		}
	}
	return nil, fmt.Errorf("multi-cloud: no adapter governs provider %q", providerKind)
}

// Rotate routes the rotation to the identity's provider adapter.
func (m *MultiProvider) Rotate(ctx context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	a, err := m.adapterFor(identity.Provider.Provider)
	if err != nil {
		return protocol.MachineIdentity{}, err
	}
	return a.Rotate(ctx, identity)
}

// Retire routes the retirement to the identity's provider adapter.
func (m *MultiProvider) Retire(ctx context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	a, err := m.adapterFor(identity.Provider.Provider)
	if err != nil {
		return protocol.MachineIdentity{}, err
	}
	return a.Retire(ctx, identity)
}

// Create routes a provisioning request to the named provider's adapter and
// returns a zero-permission identity plus a one-time secret. It returns
// ErrCreateUnsupported when the target adapter does not implement CloudCreate
// (for example a simulator) or when no adapter governs the provider.
func (m *MultiProvider) Create(ctx context.Context, providerKind, name string) (protocol.ProvisionResponse, error) {
	a, err := m.adapterFor(providerKind)
	if err != nil {
		return protocol.ProvisionResponse{}, err
	}
	creator, ok := a.(CloudCreate)
	if !ok {
		return protocol.ProvisionResponse{}, ErrCreateUnsupported
	}
	return creator.Create(ctx, name)
}
