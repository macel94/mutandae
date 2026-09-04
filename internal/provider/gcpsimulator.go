package provider

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// gcpKind is the stable provider identifier used in ProviderBindings for the
// simulated Google Cloud IAM adapter.
const gcpKind = "gcp-iam"

// gcpCredential is the provider-side representation of a service account key.
// It never holds secret material — only verification metadata. In the demo each
// service account tracks exactly one active user-managed (downloadable) JSON
// key; system-managed keys cannot be downloaded and are out of scope here.
type gcpCredential struct {
	keyID       string
	fingerprint string
	location    string
	expiresAt   time.Time
}

// serviceAccount models a Google Cloud service account that owns a renewable
// service account key.
type serviceAccount struct {
	uniqueID    string
	name        string
	email       string
	environment string
	team        string
	service     string
	purpose     string
	criticality string
	policyDays  int
	seedHealth  protocol.Health
	lastRotated time.Time
	disabled    bool
	key         gcpCredential
}

// GCPSimulator is an in-memory Google Cloud IAM adapter. It models a single
// Google Cloud project with a small set of seeded service accounts. It exposes
// the same CloudAdapter boundary as the Azure simulator so the multi-cloud
// control plane can govern GCP IAM side by side with Entra ID.
type GCPSimulator struct {
	projectID string
	region    string
	now       time.Time
	scope     Scope
	mu        sync.Mutex
	accounts  map[string]serviceAccount // keyed by service account unique id
	seq       int                       // key sequence counter
}

// NewGCPSimulator returns an adapter that simulates the given Google Cloud
// project and region at time now. now pins the simulated provider clock so the
// demo and its tests stay deterministic. Construction has no failure mode
// beyond configuration, which main wiring validates.
func NewGCPSimulator(projectID string, region string, now time.Time, scopes ...Scope) *GCPSimulator {
	scope := simulatorConstructorScope(scopes)
	now = now.UTC()
	s := &GCPSimulator{
		projectID: projectID,
		region:    region,
		now:       now,
		scope:     scope,
		accounts:  make(map[string]serviceAccount),
	}
	s.seed()
	return s
}

// NewGCPSimulatorWithScope is the explicit safe constructor for callers that
// want the simulator's zero Scope to resolve to the demo namespace.
func NewGCPSimulatorWithScope(projectID, region string, now time.Time, scope Scope) *GCPSimulator {
	return NewGCPSimulator(projectID, region, now, scope)
}

// uniqueID returns a realistic Google Cloud service account unique id (a
// 21-digit numeric project-local identifier).
func (s *GCPSimulator) uniqueID(n int) string {
	return fmt.Sprintf("%021d", n)
}

func (s *GCPSimulator) email(name string) string {
	return fmt.Sprintf("%s@%s.iam.gserviceaccount.com", name, s.projectID)
}

func (s *GCPSimulator) seed() {
	s.seq = 1
	seed := []struct {
		name        string
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
		{"inventory-broker", "production", "Commerce Infrastructure", "Stock reconciliation", "Brokers inventory stock reconciliation events", "high", 90, protocol.HealthAttention, 5 * 24 * time.Hour, 85 * 24 * time.Hour},
		{"ml-training-runtime", "staging", "Data Engineering", "ML training", "Provisions model training runtimes", "high", 90, protocol.HealthHealthy, 18 * 24 * time.Hour, 72 * 24 * time.Hour},
		{"catalog-replication", "production", "Commerce Infrastructure", "Catalog sync", "Replicates catalog data across zones", "medium", 90, protocol.HealthHealthy, 75 * 24 * time.Hour, 15 * 24 * time.Hour},
	}
	demoSeed := isDemoScope(s.scope)
	for i, item := range seed {
		uid := s.uniqueID(i + 1)
		name := item.name
		if demoSeed {
			name = demoPrefix + name
		}
		email := s.email(name)
		keyID := fmt.Sprintf("%s-service-key-%d", name, s.seq)
		s.seq++
		s.accounts[uid] = serviceAccount{
			uniqueID:    uid,
			name:        name,
			email:       email,
			environment: item.env,
			team:        item.team,
			service:     item.service,
			purpose:     item.purpose,
			criticality: item.criticality,
			policyDays:  item.policyDays,
			seedHealth:  item.health,
			lastRotated: s.now.Add(-item.lastRotated),
			key: gcpCredential{
				keyID:       keyID,
				fingerprint: fmt.Sprintf("sha256:%032x", i+1),
				location: fmt.Sprintf(
					"iam://projects/%s/serviceAccounts/%s/keys/%s",
					s.projectID, email, keyID,
				),
				expiresAt: s.now.Add(item.expiresIn),
			},
		}
	}
}

// Kind returns the stable provider identifier.
func (s *GCPSimulator) Kind() string { return gcpKind }

// Scope returns the active non-secret governance scope.
func (s *GCPSimulator) Scope() Scope { return s.scope }

// Discover returns the provider's current view of machine identities (the
// enabled service accounts in the simulated project). Control-plane governance
// IDs are left for the control plane to assign; disabled/retired service
// accounts are not (re)discovered.
func (s *GCPSimulator) Discover(_ context.Context) ([]protocol.MachineIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	identities := make([]protocol.MachineIdentity, 0, len(s.accounts))
	for _, acct := range s.accounts {
		if acct.disabled || !s.scope.Match(acct.email) {
			continue // retired/disabled or out-of-scope accounts are not discovered
		}
		identities = append(identities, s.toIdentity(acct))
	}
	return identities, nil
}

func (s *GCPSimulator) toIdentity(acct serviceAccount) protocol.MachineIdentity {
	state := protocol.StateActive
	if acct.disabled {
		state = protocol.StateRetired
	}
	return protocol.MachineIdentity{
		Name:        acct.name,
		DisplayName: acct.name,
		Environment: acct.environment,
		Provider: protocol.ProviderBinding{
			Provider:   gcpKind,
			ProviderID: acct.uniqueID,
			ProjectID:  s.projectID,
			Region:     s.region,
		},
		Ownership: protocol.Ownership{
			Team:        acct.team,
			Service:     acct.service,
			Purpose:     acct.purpose,
			Criticality: acct.criticality,
			Contacts:    []string{acct.email},
		},
		Policy: protocol.LifecyclePolicy{
			RenewalPeriod:    protocol.FormatISO8601Duration(time.Duration(acct.policyDays) * 24 * time.Hour),
			ApprovalRequired: false,
		},
		Credential: protocol.CredentialReference{
			Kind:        "service_account_key",
			Location:    acct.key.location,
			Fingerprint: acct.key.fingerprint,
			KeyID:       acct.key.keyID,
			Delivery:    "secret-manager",
		},
		State:         state,
		Health:        acct.seedHealth,
		ExpiresAt:     acct.key.expiresAt,
		LastRotatedAt: acct.lastRotated,
	}
}

func (s *GCPSimulator) accountByProviderID(identity protocol.MachineIdentity) (serviceAccount, error) {
	acct, ok := s.accounts[identity.Provider.ProviderID]
	if !ok {
		return serviceAccount{}, fmt.Errorf("%s: unknown provider id %q", gcpKind, identity.Provider.ProviderID)
	}
	return acct, nil
}

func (s *GCPSimulator) accountForPlan(id string) (serviceAccount, bool) {
	for _, acct := range s.accounts {
		if acct.uniqueID == id || acct.name == id || acct.email == id {
			return acct, true
		}
	}
	return serviceAccount{}, false
}

// Rotate performs a simulated rotation of the service account's user-managed
// key and returns provider-observed evidence (a new key id and fingerprint, plus
// the newly scheduled expiry). The control plane applies its own governed
// expiry. The demo realistically tracks only one active US-downloadable
// user-managed key per service account.
func (s *GCPSimulator) Rotate(_ context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	name := strings.TrimSpace(identity.Name)
	if name == "" {
		name = strings.TrimSpace(identity.Provider.ProviderID)
	}
	if !s.scope.Match(name) {
		return protocol.MachineIdentity{}, forbiddenScopeError(gcpKind, name, s.scope)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	acct, err := s.accountByProviderID(identity)
	if err != nil {
		return protocol.MachineIdentity{}, err
	}
	if !s.scope.Match(acct.email) {
		return protocol.MachineIdentity{}, forbiddenScopeError(gcpKind, acct.email, s.scope)
	}
	if acct.disabled {
		return protocol.MachineIdentity{}, fmt.Errorf("%s: %s is disabled/retired and cannot rotate", gcpKind, acct.name)
	}
	s.seq++
	acct.key.keyID = fmt.Sprintf("%s-service-key-%d", acct.name, s.seq)
	acct.key.fingerprint = fmt.Sprintf("sha256:%032x", s.seq+100)
	acct.key.location = fmt.Sprintf(
		"iam://projects/%s/serviceAccounts/%s/keys/%s",
		s.projectID, acct.email, acct.key.keyID,
	)
	acct.key.expiresAt = s.now.Add(time.Duration(acct.policyDays) * 24 * time.Hour)
	acct.lastRotated = s.now
	acct.seedHealth = protocol.HealthHealthy
	s.accounts[acct.uniqueID] = acct

	identity = s.toIdentity(acct)
	return identity, nil
}

// Retire disables the service account in the simulated project. Disabled
// accounts are not rediscovered.
func (s *GCPSimulator) Retire(_ context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	name := strings.TrimSpace(identity.Name)
	if name == "" {
		name = strings.TrimSpace(identity.Provider.ProviderID)
	}
	if !s.scope.Match(name) {
		return protocol.MachineIdentity{}, forbiddenScopeError(gcpKind, name, s.scope)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	acct, err := s.accountByProviderID(identity)
	if err != nil {
		return protocol.MachineIdentity{}, err
	}
	if !s.scope.Match(acct.email) {
		return protocol.MachineIdentity{}, forbiddenScopeError(gcpKind, acct.email, s.scope)
	}
	acct.disabled = true
	s.accounts[acct.uniqueID] = acct
	identity = s.toIdentity(acct)
	return identity, nil
}

// PlanRotate returns the simulator's read-only service-account key sequence.
func (s *GCPSimulator) PlanRotate(_ context.Context, id string) ([]protocol.PlannedOperation, error) {
	name := strings.TrimSpace(id)
	if name == "" {
		return nil, fmt.Errorf("%s: plan rotate requires an identity id", gcpKind)
	}
	s.mu.Lock()
	acct, ok := s.accountForPlan(name)
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%s: unknown service account %q", gcpKind, name)
	}
	if !s.scope.Match(acct.email) {
		return nil, forbiddenScopeError(gcpKind, acct.email, s.scope)
	}
	return []protocol.PlannedOperation{
		planned("gcp.create_service_account_key", acct.email, "Create a replacement user-managed service-account key.", true, false),
		planned("gcp.delete_key", acct.email, "Delete the rotated-out user-managed key after the replacement is available.", false, true),
	}, nil
}

// PlanRetire returns the simulator's read-only credential decommission step.
func (s *GCPSimulator) PlanRetire(_ context.Context, id string) ([]protocol.PlannedOperation, error) {
	name := strings.TrimSpace(id)
	if name == "" {
		return nil, fmt.Errorf("%s: plan retire requires an identity id", gcpKind)
	}
	s.mu.Lock()
	acct, ok := s.accountForPlan(name)
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%s: unknown service account %q", gcpKind, name)
	}
	if !s.scope.Match(acct.email) {
		return nil, forbiddenScopeError(gcpKind, acct.email, s.scope)
	}
	return []protocol.PlannedOperation{
		planned("gcp.delete_key", acct.email, "Delete every user-managed key so the service account has no downloadable credential.", false, true),
	}, nil
}

func (s *GCPSimulator) PlanRotateIdentity(ctx context.Context, identity protocol.MachineIdentity) ([]protocol.PlannedOperation, error) {
	id := identity.Provider.ProviderID
	if id == "" {
		id = identity.Name
	}
	return s.PlanRotate(ctx, id)
}

func (s *GCPSimulator) PlanRetireIdentity(ctx context.Context, identity protocol.MachineIdentity) ([]protocol.PlannedOperation, error) {
	id := identity.Provider.ProviderID
	if id == "" {
		id = identity.Name
	}
	return s.PlanRetire(ctx, id)
}
