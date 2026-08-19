// Package lifecycle contains the provider-neutral domain model used by the demo.
package lifecycle

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

type State string

const (
	StateRegistered State = "registered"
	StateActive     State = "active"
	StateRenewing   State = "renewing"
	StateRetired    State = "retired"
)

type RenewalHealth string

const (
	RenewalHealthy   RenewalHealth = "healthy"
	RenewalAttention RenewalHealth = "attention"
)

type Urgency string

const (
	UrgencyHealthy  Urgency = "healthy"
	UrgencyExpiring Urgency = "expiring"
	UrgencyOverdue  Urgency = "overdue"
	UrgencyRetired  Urgency = "retired"
)

var (
	ErrNotFound           = errors.New("identity not found")
	ErrInvalidTransition  = errors.New("invalid lifecycle transition")
	ErrAlreadyRetired     = errors.New("identity is retired")
	ErrRotationInProgress = errors.New("identity already has a rotation in progress")
)

type Identity struct {
	ID            string
	Name          string
	Provider      string
	Environment   string
	Owner         string
	Workload      string
	Criticality   string
	State         State
	RenewalHealth RenewalHealth
	ExpiresAt     time.Time
	LastRotatedAt time.Time
	RenewalPolicy string
	RenewalPeriod time.Duration
}

func (i Identity) Urgency(now time.Time) Urgency {
	if i.State == StateRetired {
		return UrgencyRetired
	}
	if !i.ExpiresAt.After(now) {
		return UrgencyOverdue
	}
	if i.ExpiresAt.Before(now.Add(30 * 24 * time.Hour)) {
		return UrgencyExpiring
	}
	return UrgencyHealthy
}

type Event struct {
	ID         string
	IdentityID string
	Type       string
	Summary    string
	Actor      string
	Outcome    string
	At         time.Time
}

type Store struct {
	mu         sync.RWMutex
	identities map[string]Identity
	events     map[string][]Event
	nextEvent  int
}

func NewDemoStore(now time.Time) *Store {
	now = now.UTC()
	store := &Store{
		identities: make(map[string]Identity),
		events:     make(map[string][]Event),
	}

	store.addIdentity(Identity{
		ID: "payments-api", Name: "payments-api", Provider: "Azure / Entra ID", Environment: "production",
		Owner: "Payments Platform", Workload: "Payment authorization", Criticality: "critical", State: StateActive,
		RenewalHealth: RenewalAttention, ExpiresAt: now.Add(5 * 24 * time.Hour), LastRotatedAt: now.Add(-85 * 24 * time.Hour),
		RenewalPolicy: "90-day application credential", RenewalPeriod: 90 * 24 * time.Hour,
	}, now.Add(-85*24*time.Hour), "identity.registered", "Registered from the Azure simulator", "demo-seed", "success")
	store.addEvent("payments-api", now.Add(-85*24*time.Hour), "rotation.completed", "Previous rotation verified against provider state", "rotation-simulator", "success")

	store.addIdentity(Identity{
		ID: "data-pipeline", Name: "data-pipeline", Provider: "Azure / Entra ID", Environment: "staging",
		Owner: "Data Engineering", Workload: "Warehouse ingestion", Criticality: "high", State: StateActive,
		RenewalHealth: RenewalHealthy, ExpiresAt: now.Add(18 * 24 * time.Hour), LastRotatedAt: now.Add(-72 * 24 * time.Hour),
		RenewalPolicy: "90-day application credential", RenewalPeriod: 90 * 24 * time.Hour,
	}, now.Add(-72*24*time.Hour), "identity.registered", "Registered from the Azure simulator", "demo-seed", "success")
	store.addEvent("data-pipeline", now.Add(-72*24*time.Hour), "rotation.completed", "Previous rotation verified against provider state", "rotation-simulator", "success")

	store.addIdentity(Identity{
		ID: "inventory-sync", Name: "inventory-sync", Provider: "Azure / Entra ID", Environment: "production",
		Owner: "Commerce Infrastructure", Workload: "Stock reconciliation", Criticality: "high", State: StateActive,
		RenewalHealth: RenewalHealthy, ExpiresAt: now.Add(75 * 24 * time.Hour), LastRotatedAt: now.Add(-15 * 24 * time.Hour),
		RenewalPolicy: "90-day application credential", RenewalPeriod: 90 * 24 * time.Hour,
	}, now.Add(-15*24*time.Hour), "identity.registered", "Registered from the Azure simulator", "demo-seed", "success")
	store.addEvent("inventory-sync", now.Add(-15*24*time.Hour), "rotation.completed", "Previous rotation verified against provider state", "rotation-simulator", "success")

	store.addIdentity(Identity{
		ID: "legacy-reporting", Name: "legacy-reporting", Provider: "Azure / Entra ID", Environment: "production",
		Owner: "Finance Systems", Workload: "Nightly reporting", Criticality: "medium", State: StateActive,
		RenewalHealth: RenewalAttention, ExpiresAt: now.Add(-3 * 24 * time.Hour), LastRotatedAt: now.Add(-93 * 24 * time.Hour),
		RenewalPolicy: "90-day application credential", RenewalPeriod: 90 * 24 * time.Hour,
	}, now.Add(-93*24*time.Hour), "identity.registered", "Registered from the Azure simulator", "demo-seed", "success")
	store.addEvent("legacy-reporting", now.Add(-3*24*time.Hour), "renewal.alerted", "Credential expiry passed without a verified renewal", "policy-engine", "attention")

	return store
}

func (s *Store) addIdentity(identity Identity, eventAt time.Time, eventType, summary, actor, outcome string) {
	s.identities[identity.ID] = identity
	s.addEvent(identity.ID, eventAt, eventType, summary, actor, outcome)
}

func (s *Store) addEvent(identityID string, at time.Time, eventType, summary, actor, outcome string) {
	s.nextEvent++
	s.events[identityID] = append(s.events[identityID], Event{
		ID: fmt.Sprintf("evt-%03d", s.nextEvent), IdentityID: identityID, Type: eventType,
		Summary: summary, Actor: actor, Outcome: outcome, At: at.UTC(),
	})
}

func (s *Store) List() []Identity {
	s.mu.RLock()
	defer s.mu.RUnlock()

	identities := make([]Identity, 0, len(s.identities))
	for _, identity := range s.identities {
		identities = append(identities, identity)
	}
	sort.Slice(identities, func(i, j int) bool {
		if identities[i].ExpiresAt.Equal(identities[j].ExpiresAt) {
			return identities[i].Name < identities[j].Name
		}
		return identities[i].ExpiresAt.Before(identities[j].ExpiresAt)
	})
	return identities
}

func (s *Store) Get(id string) (Identity, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	identity, ok := s.identities[id]
	return identity, ok
}

func (s *Store) Events(id string) ([]Event, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.identities[id]; !ok {
		return nil, false
	}
	events := append([]Event(nil), s.events[id]...)
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].At.Equal(events[j].At) {
			return events[i].ID > events[j].ID
		}
		return events[i].At.After(events[j].At)
	})
	return events, true
}

func Transition(from, to State) error {
	valid := (from == StateRegistered && to == StateActive) ||
		(from == StateActive && (to == StateRenewing || to == StateRetired)) ||
		(from == StateRenewing && to == StateActive)
	if !valid {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, from, to)
	}
	return nil
}

// Rotate runs the simulator's synchronous renewal flow. A production adapter
// would execute this boundary asynchronously and verify provider state before
// returning to active.
func (s *Store) Rotate(id string, now time.Time) (Identity, error) {
	now = now.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	identity, ok := s.identities[id]
	if !ok {
		return Identity{}, ErrNotFound
	}
	if identity.State == StateRetired {
		return Identity{}, ErrAlreadyRetired
	}
	if identity.State == StateRenewing {
		return Identity{}, ErrRotationInProgress
	}
	if err := Transition(identity.State, StateRenewing); err != nil {
		return Identity{}, err
	}

	identity.State = StateRenewing
	s.identities[id] = identity
	s.addEvent(id, now, "rotation.started", "Rotation requested by the operator", "demo-operator", "in_progress")

	period := identity.RenewalPeriod
	if period <= 0 {
		period = 90 * 24 * time.Hour
	}
	identity.State = StateActive
	identity.RenewalHealth = RenewalHealthy
	identity.ExpiresAt = now.Add(period)
	identity.LastRotatedAt = now
	s.identities[id] = identity
	s.addEvent(id, now, "rotation.completed", "New credential verified against simulated provider state", "rotation-simulator", "success")
	return identity, nil
}
