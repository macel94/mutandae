package provider

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// azureKind is the stable provider identifier used in ProviderBindings.
const azureKind = "azure-entra"

// credential is the provider-side representation of an application credential.
// It never holds secret material — only verification metadata.
type credential struct {
	keyID       string
	fingerprint string
	location    string
	expiresAt   time.Time
}

// appRegistration models an Entra ID application registration that owns a
// renewable client credential.
type appRegistration struct {
	objectID    string
	name        string
	displayName string
	environment string
	team        string
	service     string
	purpose     string
	criticality string
	policyDays  int
	seedHealth  protocol.Health
	lastRotated time.Time
	disabled    bool
	cred        credential
}

// Simulator is an in-memory Azure/Entra ID adapter. It starts from a fixed
// tenant and a small set of seeded application registrations.
type Simulator struct {
	tenantID string
	now      time.Time
	mu       sync.Mutex
	apps     map[string]appRegistration // keyed by objectID
	seq      int
}

// NewSimulator returns an adapter that simulates the given tenant at time now.
// now fixes the simulated provider clock so the demo and its tests stay
// deterministic. It panics-free: construction has no failure mode beyond
// configuration, which main wiring validates.
func NewSimulator(tenantID string, now time.Time) *Simulator {
	now = now.UTC()
	s := &Simulator{
		tenantID: tenantID,
		now:      now,
		apps:     make(map[string]appRegistration),
	}
	s.seed()
	return s
}

func (s *Simulator) objectID(n int) string {
	return fmt.Sprintf("00000000-0000-0000-0000-%012d", n)
}

func (s *Simulator) seed() {
	s.seq = 1
	seed := []struct {
		name        string
		display     string
		env         string
		team        string
		service     string
		purpose     string
		criticality string
		policyDays  int
		health      protocol.Health
		expiresIn   time.Duration
		lastRotated time.Duration
	}{
		{"payments-api", "payments-api", "production", "Payments Platform", "Payment authorization", "Authorizes payment processing workloads", "critical", 90, protocol.HealthAttention, 5 * 24 * time.Hour, 85 * 24 * time.Hour},
		{"data-pipeline", "data-pipeline", "staging", "Data Engineering", "Warehouse ingestion", "Ingests catalog data into the warehouse", "high", 90, protocol.HealthHealthy, 18 * 24 * time.Hour, 72 * 24 * time.Hour},
		{"inventory-sync", "inventory-sync", "production", "Commerce Infrastructure", "Stock reconciliation", "Reconciles stock across storefronts", "high", 90, protocol.HealthHealthy, 75 * 24 * time.Hour, 15 * 24 * time.Hour},
		{"legacy-reporting", "legacy-reporting", "production", "Finance Systems", "Nightly reporting", "Generates nightly finance reports", "medium", 90, protocol.HealthAttention, -3 * 24 * time.Hour, 93 * 24 * time.Hour},
	}
	for i, item := range seed {
		objID := s.objectID(i + 1)
		s.apps[objID] = appRegistration{
			objectID:    objID,
			name:        item.name,
			displayName: item.display,
			environment: item.env,
			team:        item.team,
			service:     item.service,
			purpose:     item.purpose,
			criticality: item.criticality,
			policyDays:  item.policyDays,
			seedHealth:  item.health,
			lastRotated: s.now.Add(-item.lastRotated),
			cred: credential{
				keyID:       fmt.Sprintf("%s-initial-secret", item.name),
				fingerprint: fmt.Sprintf("sha256:%032x", i+1),
				location:    fmt.Sprintf("keyvault://mutandae-vault/secrets/%s", item.name),
				expiresAt:   s.now.Add(item.expiresIn),
			},
		}
	}
}

// Kind returns the stable provider identifier.
func (s *Simulator) Kind() string { return azureKind }

// Discover returns the provider's current view of machine identities (the
// application registrations in the simulated tenant). Control-plane governance
// IDs are left for the control plane to assign.
func (s *Simulator) Discover(_ context.Context) ([]protocol.MachineIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	identities := make([]protocol.MachineIdentity, 0, len(s.apps))
	for _, app := range s.apps {
		if app.disabled {
			continue // retired/disabled registrations are not (re)discovered
		}
		identities = append(identities, s.toIdentity(app))
	}
	return identities, nil
}

func (s *Simulator) toIdentity(app appRegistration) protocol.MachineIdentity {
	state := protocol.StateActive
	if app.disabled {
		state = protocol.StateRetired
	}
	return protocol.MachineIdentity{
		Name:        app.name,
		DisplayName: app.displayName,
		Environment: app.environment,
		Provider: protocol.ProviderBinding{
			Provider:   azureKind,
			ProviderID: app.objectID,
			TenantID:   s.tenantID,
			ObjectID:   app.objectID,
			Region:     "westeurope",
		},
		Ownership: protocol.Ownership{
			Team:        app.team,
			Service:     app.service,
			Purpose:     app.purpose,
			Criticality: app.criticality,
			Contacts:    []string{app.name + "@mutandae.example"},
		},
		Policy: protocol.LifecyclePolicy{
			RenewalPeriod:    protocol.FormatISO8601Duration(time.Duration(app.policyDays) * 24 * time.Hour),
			ApprovalRequired: false,
		},
		Credential: protocol.CredentialReference{
			Kind:        "client_secret",
			Location:    app.cred.location,
			Fingerprint: app.cred.fingerprint,
			KeyID:       app.cred.keyID,
			Delivery:    "keyvault-ref",
		},
		State:         state,
		Health:        app.seedHealth,
		ExpiresAt:     app.cred.expiresAt,
		LastRotatedAt: app.lastRotated,
	}
}

func (s *Simulator) appByProviderID(identity protocol.MachineIdentity) (appRegistration, error) {
	app, ok := s.apps[identity.Provider.ProviderID]
	if !ok {
		return appRegistration{}, fmt.Errorf("%s: unknown provider id %q", azureKind, identity.Provider.ProviderID)
	}
	return app, nil
}

// Rotate performs a simulated rotation of the identity's credential and returns
// provider-observed evidence (a new key id and credential fingerprint, plus the
// newly scheduled expiry). The control plane applies its own governed expiry.
func (s *Simulator) Rotate(_ context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	app, err := s.appByProviderID(identity)
	if err != nil {
		return protocol.MachineIdentity{}, err
	}
	if app.disabled {
		return protocol.MachineIdentity{}, fmt.Errorf("%s: %s is disabled/retired and cannot rotate", azureKind, app.name)
	}
	s.seq++
	app.cred.keyID = fmt.Sprintf("%s-credential-%d", app.name, s.seq)
	app.cred.fingerprint = fmt.Sprintf("sha256:%032x", s.seq+100)
	app.cred.expiresAt = s.now.Add(time.Duration(app.policyDays) * 24 * time.Hour)
	app.lastRotated = s.now
	app.seedHealth = protocol.HealthHealthy
	s.apps[app.objectID] = app

	identity = s.toIdentity(app)
	return identity, nil
}

// Retire disables the identity's registration in the simulated tenant.
func (s *Simulator) Retire(_ context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	app, err := s.appByProviderID(identity)
	if err != nil {
		return protocol.MachineIdentity{}, err
	}
	app.disabled = true
	s.apps[app.objectID] = app
	identity = s.toIdentity(app)
	return identity, nil
}
