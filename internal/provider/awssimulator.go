package provider

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// awsKind is the stable provider identifier used in ProviderBindings.
const awsKind = "aws-iam"

// accessKey is the provider-side representation of a single AWS access key.
// It never holds secret material — only verification metadata (the access key
// id and its fingerprint).
type accessKey struct {
	keyID       string
	fingerprint string
	location    string
	expiresAt   time.Time
}

// iamUser models an AWS IAM user that owns a renewable access key.
type iamUser struct {
	name        string
	environment string
	team        string
	service     string
	purpose     string
	criticality string
	policyDays  int
	seedHealth  protocol.Health
	lastRotated time.Time
	disabled    bool
	key         accessKey
}

// AWSSimulator is an in-memory AWS IAM adapter. It starts from a fixed account
// and region and a small set of seeded IAM users each owning an access key.
type AWSSimulator struct {
	accountID string
	region    string
	now       time.Time
	scope     Scope
	mu        sync.Mutex
	users     map[string]iamUser // keyed by IAM user name
	seq       int
}

// NewAWSSimulator returns an adapter that simulates the given AWS account at
// time now. An omitted scope keeps the historical all-identities simulator
// used by existing local fixtures; production composition passes an explicit
// DemoScope. Supplying a zero Scope uses the safe mutandae-demo-* default.
func NewAWSSimulator(accountID string, region string, now time.Time, scopes ...Scope) *AWSSimulator {
	scope := simulatorConstructorScope(scopes)
	now = now.UTC()
	s := &AWSSimulator{
		accountID: accountID,
		region:    region,
		now:       now,
		scope:     scope,
		users:     make(map[string]iamUser),
	}
	s.seed()
	return s
}

// NewAWSSimulatorWithScope is the explicit safe constructor for callers that
// want the simulator's zero Scope to resolve to the demo namespace.
func NewAWSSimulatorWithScope(accountID, region string, now time.Time, scope Scope) *AWSSimulator {
	return NewAWSSimulator(accountID, region, now, scope)
}

func (s *AWSSimulator) seed() {
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
		{"orders-deployer", "production", "Orders Platform", "Order deployment", "Deploys order processing workloads", "high", 90, protocol.HealthAttention, 5 * 24 * time.Hour, 85 * 24 * time.Hour},
		{"data-exporting", "staging", "Data Engineering", "Export pipeline", "Exports catalog data to downstream systems", "high", 90, protocol.HealthHealthy, 18 * 24 * time.Hour, 72 * 24 * time.Hour},
		{"metrics-publisher", "production", "Observability", "Metrics publishing", "Publishes application metrics", "medium", 90, protocol.HealthHealthy, 75 * 24 * time.Hour, 15 * 24 * time.Hour},
	}
	demoSeed := isDemoScope(s.scope)
	for i, item := range seed {
		name := item.name
		if demoSeed {
			name = demoPrefix + name
		}
		s.users[name] = iamUser{
			name:        name,
			environment: item.env,
			team:        item.team,
			service:     item.service,
			purpose:     item.purpose,
			criticality: item.criticality,
			policyDays:  item.policyDays,
			seedHealth:  item.health,
			lastRotated: s.now.Add(-item.lastRotated),
			key: accessKey{
				keyID:       fmt.Sprintf("%s-infra-key", name),
				fingerprint: fmt.Sprintf("sha256:%032x", i+1),
				location:    fmt.Sprintf("iam://%s/user/%s", s.accountID, name),
				expiresAt:   s.now.Add(item.expiresIn),
			},
		}
	}
}

// Kind returns the stable provider identifier.
func (s *AWSSimulator) Kind() string { return awsKind }

// Scope returns the active non-secret governance scope.
func (s *AWSSimulator) Scope() Scope { return s.scope }

// Discover returns the provider's current view of machine identities (the
// enabled IAM users in the simulated account). Control-plane governance IDs
// are left for the control plane to assign.
func (s *AWSSimulator) Discover(_ context.Context) ([]protocol.MachineIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	identities := make([]protocol.MachineIdentity, 0, len(s.users))
	for _, user := range s.users {
		if user.disabled || !s.scope.Match(user.name) {
			continue // retired/disabled or out-of-scope users are not discovered
		}
		identities = append(identities, s.toIdentity(user))
	}
	return identities, nil
}

func (s *AWSSimulator) toIdentity(user iamUser) protocol.MachineIdentity {
	state := protocol.StateActive
	if user.disabled {
		state = protocol.StateRetired
	}
	contacts := []string{user.name + "@aws.mutandae.example"}
	return protocol.MachineIdentity{
		Name:        user.name,
		DisplayName: user.name,
		Environment: user.environment,
		Provider: protocol.ProviderBinding{
			Provider:   awsKind,
			ProviderID: user.name,
			AccountID:  s.accountID,
			Region:     s.region,
		},
		Ownership: protocol.Ownership{
			Team:        user.team,
			Service:     user.service,
			Purpose:     user.purpose,
			Criticality: user.criticality,
			Contacts:    contacts,
		},
		Policy: protocol.LifecyclePolicy{
			RenewalPeriod:    protocol.FormatISO8601Duration(time.Duration(user.policyDays) * 24 * time.Hour),
			ApprovalRequired: false,
		},
		Credential: protocol.CredentialReference{
			Kind:        "access_key",
			Location:    user.key.location,
			Fingerprint: user.key.fingerprint,
			KeyID:       user.key.keyID,
			Delivery:    "secret-manager",
		},
		State:         state,
		Health:        user.seedHealth,
		ExpiresAt:     user.key.expiresAt,
		LastRotatedAt: user.lastRotated,
	}
}

func (s *AWSSimulator) userByName(identity protocol.MachineIdentity) (iamUser, error) {
	user, ok := s.users[identity.Provider.ProviderID]
	if !ok {
		return iamUser{}, fmt.Errorf("%s: unknown provider id %q", awsKind, identity.Provider.ProviderID)
	}
	return user, nil
}

// Rotate performs a simulated rotation of the IAM user's access key and
// returns provider-observed evidence (a new key id and fingerprint, plus the
// newly scheduled expiry). The control plane applies its own governed expiry.
func (s *AWSSimulator) Rotate(_ context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	name := strings.TrimSpace(identity.Provider.ProviderID)
	if name == "" {
		name = strings.TrimSpace(identity.Name)
	}
	if !s.scope.Match(name) {
		return protocol.MachineIdentity{}, forbiddenScopeError(awsKind, name, s.scope)
	}
	identity.Provider.ProviderID = name
	user, err := s.userByName(identity)
	if err != nil {
		return protocol.MachineIdentity{}, err
	}
	if user.disabled {
		return protocol.MachineIdentity{}, fmt.Errorf("%s: %s is disabled/retired and cannot rotate", awsKind, user.name)
	}
	s.seq++
	user.key.keyID = fmt.Sprintf("%s-access-key-%d", user.name, s.seq)
	user.key.fingerprint = fmt.Sprintf("sha256:%032x", s.seq+200)
	user.key.expiresAt = s.now.Add(time.Duration(user.policyDays) * 24 * time.Hour)
	user.lastRotated = s.now
	user.seedHealth = protocol.HealthHealthy
	s.users[user.name] = user

	return s.toIdentity(user), nil
}

// Retire disables the IAM user in the simulated account.
func (s *AWSSimulator) Retire(_ context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	name := strings.TrimSpace(identity.Provider.ProviderID)
	if name == "" {
		name = strings.TrimSpace(identity.Name)
	}
	if !s.scope.Match(name) {
		return protocol.MachineIdentity{}, forbiddenScopeError(awsKind, name, s.scope)
	}
	identity.Provider.ProviderID = name
	user, err := s.userByName(identity)
	if err != nil {
		return protocol.MachineIdentity{}, err
	}
	user.disabled = true
	s.users[user.name] = user
	return s.toIdentity(user), nil
}

// PlanRotate returns the simulator's read-only replacement sequence.
func (s *AWSSimulator) PlanRotate(_ context.Context, id string) ([]protocol.PlannedOperation, error) {
	name := strings.TrimSpace(id)
	if name == "" {
		return nil, fmt.Errorf("%s: plan rotate requires an identity id", awsKind)
	}
	if !s.scope.Match(name) {
		return nil, forbiddenScopeError(awsKind, name, s.scope)
	}
	s.mu.Lock()
	_, ok := s.users[name]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%s: unknown provider id %q", awsKind, name)
	}
	return []protocol.PlannedOperation{
		planned("aws.create_access_key", name, "Create a replacement access key and make it the active credential.", true, false),
		planned("aws.revoke_old_access_key", name, "Revoke the previous access key after the replacement is available.", false, true),
	}, nil
}

// PlanRetire returns the simulator's read-only decommission sequence.
func (s *AWSSimulator) PlanRetire(_ context.Context, id string) ([]protocol.PlannedOperation, error) {
	name := strings.TrimSpace(id)
	if name == "" {
		return nil, fmt.Errorf("%s: plan retire requires an identity id", awsKind)
	}
	if !s.scope.Match(name) {
		return nil, forbiddenScopeError(awsKind, name, s.scope)
	}
	s.mu.Lock()
	_, ok := s.users[name]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%s: unknown provider id %q", awsKind, name)
	}
	return []protocol.PlannedOperation{
		planned("aws.disable_user", name, "Disable the IAM user so it is no longer governed or discoverable.", true, true),
	}, nil
}

func (s *AWSSimulator) PlanRotateIdentity(ctx context.Context, identity protocol.MachineIdentity) ([]protocol.PlannedOperation, error) {
	id := identity.Provider.ProviderID
	if id == "" {
		id = identity.Name
	}
	return s.PlanRotate(ctx, id)
}

func (s *AWSSimulator) PlanRetireIdentity(ctx context.Context, identity protocol.MachineIdentity) ([]protocol.PlannedOperation, error) {
	id := identity.Provider.ProviderID
	if id == "" {
		id = identity.Name
	}
	return s.PlanRetire(ctx, id)
}
