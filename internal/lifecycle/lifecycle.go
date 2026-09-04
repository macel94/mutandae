package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// Store is an in-memory control-plane implementation of the μTandae Protocol
// lifecycle. It stores protocol-native MachineIdentities plus their audit
// events and rotation runs, and orchestrates lifecycle changes with a provider
// Adapter. It is not durable or horizontally shared; it exists to make the
// public demo runnable and testable without a database.
type Store struct {
	mu          sync.RWMutex
	adapter     Adapter
	repository  Repository
	commonVault CommonVault
	identities  map[string]protocol.MachineIdentity
	events      map[string][]protocol.LifecycleEvent
	runs        map[string][]protocol.RotationRun
	nextEvent   int
	nextRun     int
	watchCancel context.CancelFunc
	watchDone   chan struct{}
}

// Option configures optional Store collaborators at construction time.
type Option func(*storeOptions)

// storeOptions carries the collaborators an Option may inject.
type storeOptions struct {
	commonVault CommonVault
}

// WithCommonVault binds the cluster μVault mirror to the store. A nil vault
// (the default) leaves the store's behavior unchanged: credentials are
// delivered only to the provider-native vault when the adapter supports it.
func WithCommonVault(vault CommonVault) Option {
	return func(options *storeOptions) {
		if vault != nil {
			options.commonVault = vault
		}
	}
}

// NewStore constructs an in-memory control-plane store bound to the given
// provider adapter. NewPersistentStore adds Redis-backed state and pub/sub.
// Options may bind optional collaborators such as the cluster μVault mirror.
func NewStore(ctx context.Context, now time.Time, adapter Adapter, options ...Option) (*Store, error) {
	return newStore(ctx, now, adapter, nil, options)
}

// NewPersistentStore restores an environment-scoped snapshot from repository.
// On first boot, it discovers the provider seed once and persists that state.
func NewPersistentStore(ctx context.Context, now time.Time, adapter Adapter, repository Repository, options ...Option) (*Store, error) {
	return newStore(ctx, now, adapter, repository, options)
}

func newStore(ctx context.Context, now time.Time, adapter Adapter, repository Repository, options []Option) (*Store, error) {
	if adapter == nil {
		return nil, ErrAdapterRequired
	}
	opts := storeOptions{}
	for _, option := range options {
		if option != nil {
			option(&opts)
		}
	}
	store := &Store{
		adapter:     adapter,
		repository:  repository,
		commonVault: opts.commonVault,
		identities:  make(map[string]protocol.MachineIdentity),
		events:      make(map[string][]protocol.LifecycleEvent),
		runs:        make(map[string][]protocol.RotationRun),
	}
	if repository != nil {
		snapshot, err := repository.Load(ctx)
		if err == nil {
			store.restoreLocked(snapshot)
			if err := store.startWatcher(); err != nil {
				return nil, err
			}
			return store, nil
		}
		if !errors.Is(err, ErrNoSnapshot) {
			return nil, err
		}
	}
	discovered, err := adapter.Discover(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: discover: %v", ErrProviderFailure, err)
	}
	for _, identity := range discovered {
		if err := store.adopt(fixIdentity(identity), now); err != nil {
			return nil, err
		}
	}
	if repository != nil {
		if err := repository.Save(ctx, store.snapshotLocked()); err != nil {
			return nil, err
		}
		if err := store.startWatcher(); err != nil {
			return nil, err
		}
	}
	return store, nil
}

// fixIdentity fills the governance ID from the friendly name (demo convention:
// provider registrations are discovered without a control-plane ID).
func fixIdentity(identity protocol.MachineIdentity) protocol.MachineIdentity {
	if identity.ID == "" {
		identity.ID = identity.Name
	}
	if identity.Health == "" {
		identity.Health = protocol.HealthHealthy
	}
	return identity
}

// adopt records a discovered identity as governed (active) and audits both the
// discovery and the registration.
func (s *Store) adopt(identity protocol.MachineIdentity, now time.Time) error {
	now = now.UTC()
	identity.CreatedAt = now
	identity.UpdatedAt = now
	identity.State = protocol.StateActive
	if err := protocol.ValidateIdentity(&identity); err != nil {
		return fmt.Errorf("adapter returned non-conformant identity %q: %w", identity.Name, err)
	}
	s.identities[identity.ID] = identity
	s.addEvent(identity.ID, now, protocol.EventIdentityDiscovered,
		fmt.Sprintf("Discovered %s in the %s tenant", identity.Name, identity.Provider.Provider),
		protocol.ActorDiscovery, protocol.OutcomeSuccess,
		map[string]string{"provider_id": identity.Provider.ProviderID}, "")
	s.addEvent(identity.ID, now, protocol.EventIdentityRegistered,
		fmt.Sprintf("Registered %s into governance", identity.Name),
		protocol.ActorControlPlane, protocol.OutcomeSuccess, nil, "")
	return nil
}

func (s *Store) addEvent(identityID string, at time.Time, eventType protocol.EventType, summary, actor string, outcome protocol.Outcome, details map[string]string, runID string) {
	s.nextEvent++
	event := protocol.LifecycleEvent{
		ID: fmt.Sprintf("evt-%03d", s.nextEvent), IdentityID: identityID, Type: eventType,
		Summary: summary, Actor: actor, Outcome: outcome, At: at.UTC(), Details: details,
	}
	if runID != "" {
		// Rotation workflow events share the rotation run's identifier as both
		// the correlation id and the run reference so consumers can group a
		// rotation.started → rotation.completed pair without extra joins.
		event.CorrelationID = runID
		event.RunID = runID
	}
	s.events[identityID] = append(s.events[identityID], event)
}

// List returns governed identities ordered by expiry ascending.
func (s *Store) List() []protocol.MachineIdentity {
	s.mu.RLock()
	defer s.mu.RUnlock()

	identities := make([]protocol.MachineIdentity, 0, len(s.identities))
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

// Get returns a single governed identity.
func (s *Store) Get(id string) (protocol.MachineIdentity, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	identity, ok := s.identities[id]
	return identity, ok
}

// Events returns the audit events for an identity, newest first.
func (s *Store) Events(id string) ([]protocol.LifecycleEvent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.identities[id]; !ok {
		return nil, false
	}
	events := append([]protocol.LifecycleEvent(nil), s.events[id]...)
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].At.Equal(events[j].At) {
			return events[i].ID > events[j].ID
		}
		return events[i].At.After(events[j].At)
	})
	return events, true
}

// Runs returns the rotation runs for an identity, newest first.
func (s *Store) Runs(id string) ([]protocol.RotationRun, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.identities[id]; !ok {
		return nil, false
	}
	runs := append([]protocol.RotationRun(nil), s.runs[id]...)
	sort.SliceStable(runs, func(i, j int) bool {
		if runs[i].RequestedAt.Equal(runs[j].RequestedAt) {
			return runs[i].ID > runs[j].ID
		}
		return runs[i].RequestedAt.After(runs[j].RequestedAt)
	})
	return runs, true
}

// Provision creates a brand-new, zero-permission identity in a real tenant via
// the adapter's Create, then adopts it into governance. The one-time secret in
// the returned response is never persisted: the stored identity records only
// the safe credential reference, and any audit trail carries key ids/locations.
func (s *Store) Provision(ctx context.Context, req protocol.ProvisionRequest, now time.Time) (protocol.ProvisionResponse, error) {
	provider := strings.TrimSpace(req.Provider)
	if provider == "" {
		return protocol.ProvisionResponse{}, fmt.Errorf("%w: provider is required", protocol.ErrConformance)
	}
	prov, ok := s.adapter.(Provisioner)
	if !ok {
		return protocol.ProvisionResponse{}, ErrProviderFailure
	}

	resp, err := prov.Create(ctx, provider, req.Purpose)
	if err != nil {
		return protocol.ProvisionResponse{}, providerOperationError(err)
	}
	if resp.Identity.Name == "" {
		return protocol.ProvisionResponse{}, fmt.Errorf("%w: %s adapter returned no identity", ErrProviderFailure, provider)
	}

	identity := fixIdentity(resp.Identity)
	identity.State = protocol.StateActive
	identity.Health = protocol.HealthHealthy
	identity.CreatedAt = now.UTC()
	identity.UpdatedAt = now.UTC()
	if err := protocol.ValidateIdentity(&identity); err != nil {
		// Timely cleanup so an unadoptable identity is not left dangling.
		_, _ = s.adapter.Retire(ctx, identity)
		return protocol.ProvisionResponse{}, fmt.Errorf("provisioned identity is not conformant: %w", err)
	}

	s.mu.Lock()
	s.identities[identity.ID] = identity
	s.addEvent(identity.ID, now.UTC(), protocol.EventIdentityDiscovered,
		fmt.Sprintf("Provisioned %s in the %s tenant", identity.Name, provider),
		protocol.ActorDiscovery, protocol.OutcomeSuccess,
		map[string]string{"provider_id": identity.Provider.ProviderID}, "")
	s.addEvent(identity.ID, now.UTC(), protocol.EventIdentityRegistered,
		fmt.Sprintf("Registered %s into governance", identity.Name),
		req.RequestedByOrDefault(), protocol.OutcomeSuccess, nil, "")
	s.mu.Unlock()
	// Deliver the freshly issued credential to the selected provider-native
	// vault and mirror it to the cluster μVault. The one-time response
	// disclosure stays intact; the vault copies are what make later, audited
	// retrieval (Use) possible. Each delivery records its own independent
	// audit event, and the native reference wins for the response whenever it
	// exists — the cluster copy is the fallback reference and its own
	// metadata entry.
	nativeRef := s.deliverToVault(ctx, identity, resp.KeyID, resp.OneTimeSecret, now)
	commonRef := s.mirrorToCommonVault(ctx, identity, resp.KeyID, resp.OneTimeSecret, now)
	if nativeRef != nil {
		resp.Vault = nativeRef
		identity.Metadata = withVaultMetadata(identity.Metadata, nativeRef)
	}
	if commonRef != nil {
		identity.Metadata = withCommonVaultMetadata(identity.Metadata, commonRef)
		if nativeRef == nil {
			// Without a native copy the cluster μVault copy is the one
			// retrievable reference the response can honestly advertise.
			resp.Vault = commonRef
		}
	}
	if nativeRef != nil || commonRef != nil {
		identity.UpdatedAt = now.UTC()
		s.mu.Lock()
		s.identities[identity.ID] = identity
		s.mu.Unlock()
	}
	if err := s.persistLocked(ctx); err != nil {
		return protocol.ProvisionResponse{}, err
	}

	// Deliver the one-time credential only in this response; it is not stored.
	resp.Identity = identity
	resp.APIVersion = protocol.Version
	return resp, nil
}

// Register provisions a new machine identity into governance. It validates the
// request against protocol conformance rules, assigns an ID when absent, and
// audits registration.
func (s *Store) Register(ctx context.Context, req protocol.RegisterRequest, now time.Time) (protocol.RegisterResponse, error) {
	if err := registerRequestConforms(req); err != nil {
		return protocol.RegisterResponse{}, err
	}
	policyDuration, err := protocol.ParseISO8601Duration(req.Policy.RenewalPeriod)
	if err != nil {
		return protocol.RegisterResponse{}, fmt.Errorf("%w: renewal_period: %v", protocol.ErrConformance, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now = now.UTC()

	if req.ID == "" {
		req.ID = req.Name
	}
	if _, exists := s.identities[req.ID]; exists {
		return protocol.RegisterResponse{}, fmt.Errorf("identity %q already registered", req.ID)
	}

	identity := protocol.MachineIdentity{
		ID:          req.ID,
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Namespace:   req.Namespace,
		Environment: req.Environment,
		Provider:    req.Provider,
		Ownership:   req.Ownership,
		Policy:      req.Policy,
		Credential:  req.Credential,
		State:       protocol.StateActive,
		Health:      protocol.HealthHealthy,
		ExpiresAt:   now.Add(policyDuration),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	s.identities[identity.ID] = identity
	s.addEvent(identity.ID, now, protocol.EventIdentityRegistered,
		fmt.Sprintf("Registered %s into governance", identity.Name),
		req.RequestedByOrDefault(), protocol.OutcomeSuccess, nil, "")

	if err := s.persistLocked(ctx); err != nil {
		return protocol.RegisterResponse{}, err
	}
	events := s.eventsSnapshotLocked(identity.ID)
	return protocol.RegisterResponse{APIVersion: protocol.Version, Identity: identity, Events: events}, nil
}

func registerRequestConforms(req protocol.RegisterRequest) error {
	var errs protocol.ValidationErrors
	if req.Name == "" {
		errs = append(errs, "name is required")
	}
	if req.Provider.Provider == "" {
		errs = append(errs, "provider.provider is required")
	}
	if req.Provider.ProviderID == "" {
		errs = append(errs, "provider.provider_id is required")
	}
	if req.Ownership.Team == "" {
		errs = append(errs, "ownership.team is required")
	}
	if req.Policy.RenewalPeriod == "" {
		errs = append(errs, "policy.renewal_period is required")
	} else if _, err := protocol.ParseISO8601Duration(req.Policy.RenewalPeriod); err != nil {
		errs = append(errs, "policy.renewal_period is not a valid ISO-8601 duration")
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: %v", protocol.ErrConformance, errs)
	}
	return nil
}

// plan builds a provider-neutral dry-run plan. Provider planners receive the
// full governed identity when the adapter supports IdentityPlanner, which is
// important for composites where a lifecycle id alone does not identify the
// cloud. Older adapters fall back to a store-level plan derived from the known
// credential state.
func (s *Store) plan(ctx context.Context, identity protocol.MachineIdentity, rotate bool) (protocol.Plan, error) {
	var (
		operations []protocol.PlannedOperation
		err        error
	)
	if planner, ok := s.adapter.(IdentityPlanner); ok {
		if rotate {
			operations, err = planner.PlanRotateIdentity(ctx, identity)
		} else {
			operations, err = planner.PlanRetireIdentity(ctx, identity)
		}
	} else if planner, ok := s.adapter.(Planner); ok {
		id := identity.Provider.ProviderID
		if strings.TrimSpace(id) == "" {
			id = identity.Name
		}
		if rotate {
			operations, err = planner.PlanRotate(ctx, id)
		} else {
			operations, err = planner.PlanRetire(ctx, id)
		}
	} else {
		name := identity.Name
		if rotate {
			operations = []protocol.PlannedOperation{
				{Op: "lifecycle.create_credential", Identity: name, Detail: "Create a replacement credential without applying provider changes.", Reversible: true},
				{Op: "lifecycle.verify_credential", Identity: name, Detail: "Verify the replacement credential before it becomes current.", Reversible: true},
				{Op: "lifecycle.revoke_previous_credential", Identity: name, Detail: "Revoke the previous credential after successful verification.", Destructive: true},
			}
		} else {
			operations = []protocol.PlannedOperation{
				{Op: "lifecycle.revoke_credential", Identity: name, Detail: "Revoke the governed credential without applying provider changes.", Destructive: true},
				{Op: "lifecycle.mark_retired", Identity: name, Detail: "Mark the identity retired after provider decommissioning succeeds.", Reversible: false, Destructive: true},
			}
		}
	}
	if err != nil {
		return protocol.Plan{}, providerOperationError(err)
	}
	plan := protocol.Plan{
		DryRun:      true,
		Operations:  operations,
		ExpiresHint: "Re-plan immediately before applying; provider state may change.",
	}
	if err := protocol.ValidatePlan(&plan); err != nil {
		return protocol.Plan{}, fmt.Errorf("%w: planner returned an invalid plan: %v", ErrConformance, err)
	}
	return plan, nil
}

func providerOperationError(err error) error {
	if errors.Is(err, ErrForbidden) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrProviderFailure, err)
}

// Rotate starts and completes a renewal/rotation through the provider adapter,
// emitting a correlated RotationRun and auditing events. On adapter failure the
// identity returns to active with attention health so a retry stays possible.
// A dry run exits before allocating a run or invoking any mutating method.
func (s *Store) Rotate(ctx context.Context, req protocol.RotateRequest, now time.Time) (protocol.RotateResponse, error) {
	if err := protocol.ValidateRotateRequest(&req); err != nil {
		return protocol.RotateResponse{}, err
	}
	s.mu.Lock()
	now = now.UTC()

	identity, ok := s.identities[req.ID]
	if !ok {
		s.mu.Unlock()
		return protocol.RotateResponse{}, ErrNotFound
	}
	if identity.State == protocol.StateRetired {
		s.mu.Unlock()
		return protocol.RotateResponse{}, ErrAlreadyRetired
	}
	if identity.State == protocol.StateRenewing {
		s.mu.Unlock()
		return protocol.RotateResponse{}, ErrRotationInProgress
	}
	if !protocol.CanTransition(identity.State, protocol.StateRenewing) {
		s.mu.Unlock()
		return protocol.RotateResponse{}, fmt.Errorf("%w: %s -> renewing", ErrInvalidTransition, identity.State)
	}
	if req.DryRun {
		s.mu.Unlock()
		plan, err := s.plan(ctx, identity, true)
		if err != nil {
			return protocol.RotateResponse{}, err
		}
		return protocol.RotateResponse{APIVersion: protocol.Version, Identity: identity, Plan: &plan}, nil
	}

	s.nextRun++
	runID := fmt.Sprintf("run-%03d", s.nextRun)
	operator := req.RequestedByOrDefault()
	run := protocol.RotationRun{
		ID: runID, IdentityID: identity.ID, Status: protocol.RotationRunning,
		RequestedBy: operator, RequestedAt: now, StartedAt: now,
	}
	runIndex := len(s.runs[identity.ID])
	s.runs[identity.ID] = append(s.runs[identity.ID], run)

	identity.State = protocol.StateRenewing
	s.identities[identity.ID] = identity
	s.addEvent(identity.ID, now, protocol.EventRotationRequested,
		"Rotation requested by "+operator, operator, protocol.OutcomeInProgress,
		map[string]string{"reason": req.Reason}, runID)
	s.addEvent(identity.ID, now, protocol.EventRotationStarted,
		"Rotation dispatched to "+identity.Provider.Provider, protocol.ActorControlPlane,
		protocol.OutcomeInProgress, nil, runID)

	// The demo holds the store lock while invoking the (in-memory) provider
	// adapter so the renewing state cannot be mutated concurrently. A production
	// control plane should release the lock, execute the provider call
	// asynchronously, and reconcile the outcome when it resolves.
	adapter := s.adapter
	providerView, adapterErr := adapter.Rotate(ctx, identity)

	if adapterErr != nil {
		identity.State = protocol.StateActive
		identity.Health = protocol.HealthAttention
		s.identities[identity.ID] = identity
		run.Status = protocol.RotationFailed
		run.Outcome = protocol.OutcomeFailure
		run.FinishedAt = now
		run.Error = adapterErr.Error()
		s.runs[identity.ID][runIndex] = run
		s.addEvent(identity.ID, now, protocol.EventRotationFailed,
			"Rotation failed at the provider: "+adapterErr.Error(), protocol.ActorProviderAdapter,
			protocol.OutcomeFailure, nil, runID)
		if persistErr := s.persistLocked(ctx); persistErr != nil {
			s.mu.Unlock()
			return protocol.RotateResponse{}, persistErr
		}
		s.mu.Unlock()
		return protocol.RotateResponse{}, providerOperationError(adapterErr)
	}

	// Governance is authoritative for expiry; the provider supplies evidence.
	duration, _ := protocol.ParseISO8601Duration(identity.Policy.RenewalPeriod)
	identity = providerView
	identity.ID = req.ID
	identity.State = protocol.StateActive
	identity.Health = protocol.HealthHealthy
	identity.ExpiresAt = now.Add(duration)
	identity.LastRotatedAt = now
	identity.UpdatedAt = now
	s.identities[identity.ID] = identity

	run.Status = protocol.RotationSucceeded
	run.Outcome = protocol.OutcomeSuccess
	run.FinishedAt = now
	run.Evidence = identity.Credential
	s.runs[identity.ID][runIndex] = run
	s.addEvent(identity.ID, now, protocol.EventRotationCompleted,
		"New credential verified against provider state", protocol.ActorProviderAdapter,
		protocol.OutcomeSuccess,
		map[string]string{"key_id": identity.Credential.KeyID, "fingerprint": identity.Credential.Fingerprint}, runID)
	s.mu.Unlock()
	// Deliver the renewed credential to the vault as a new secret version so
	// consumers of the old version can never be stranded, mirroring it to the
	// cluster μVault. Failures surface as attention events and never roll
	// back the completed rotation. Each delivery records its own independent
	// audit event; the metadata update substitutes the cluster copy when no
	// native reference was produced.
	if issuer, ok := s.adapter.(OneTimeSecretor); ok {
		if renewed := issuer.ConsumeOneTimeSecret(identity.Provider.Provider); renewed != "" {
			nativeRef := s.deliverToVault(ctx, identity, identity.Credential.KeyID, renewed, now)
			commonRef := s.mirrorToCommonVault(ctx, identity, identity.Credential.KeyID, renewed, now)
			if nativeRef != nil {
				identity.Metadata = withVaultMetadata(identity.Metadata, nativeRef)
			}
			if commonRef != nil {
				identity.Metadata = withCommonVaultMetadata(identity.Metadata, commonRef)
			}
			if nativeRef != nil || commonRef != nil {
				identity.UpdatedAt = now
				s.mu.Lock()
				s.identities[identity.ID] = identity
				s.mu.Unlock()
			}
		}
	}
	s.mu.Lock()
	if err := s.persistLocked(ctx); err != nil {
		s.mu.Unlock()
		return protocol.RotateResponse{}, err
	}

	events := s.eventsSnapshotLocked(identity.ID)
	s.mu.Unlock()
	return protocol.RotateResponse{
		APIVersion: protocol.Version, Identity: identity, Rotation: run, Events: events,
	}, nil
}

// Retire decommissions an identity through an explicit lifecycle transition,
// requiring an explicit confirmation. The provider adapter is then asked to
// disable the registration.
func (s *Store) Retire(ctx context.Context, req protocol.RetireRequest, now time.Time) (protocol.RetireResponse, error) {
	if err := protocol.ValidateRetireRequest(&req); err != nil {
		return protocol.RetireResponse{}, err
	}
	if !req.DryRun && !req.Confirm {
		return protocol.RetireResponse{}, ErrConfirmationNeeded
	}
	s.mu.Lock()
	now = now.UTC()

	identity, ok := s.identities[req.ID]
	if !ok {
		s.mu.Unlock()
		return protocol.RetireResponse{}, ErrNotFound
	}
	if identity.State == protocol.StateRetired {
		s.mu.Unlock()
		return protocol.RetireResponse{}, ErrAlreadyRetired
	}
	if !protocol.CanTransition(identity.State, protocol.StateRetired) {
		s.mu.Unlock()
		return protocol.RetireResponse{}, fmt.Errorf("%w: %s -> retired", ErrInvalidTransition, identity.State)
	}
	if req.DryRun {
		s.mu.Unlock()
		plan, err := s.plan(ctx, identity, false)
		if err != nil {
			return protocol.RetireResponse{}, err
		}
		return protocol.RetireResponse{APIVersion: protocol.Version, Identity: identity, Plan: &plan}, nil
	}

	adapter := s.adapter
	providerView, adapterErr := adapter.Retire(ctx, identity)
	if adapterErr != nil {
		s.mu.Unlock()
		return protocol.RetireResponse{}, providerOperationError(adapterErr)
	}

	operator := req.RequestedByOrDefault()
	identity = providerView
	identity.ID = req.ID
	identity.State = protocol.StateRetired
	identity.Health = protocol.HealthAttention
	identity.UpdatedAt = now
	s.identities[identity.ID] = identity
	s.addEvent(identity.ID, now, protocol.EventIdentityRetired,
		"Retired "+identity.Name+" ("+req.Reason+")", operator, protocol.OutcomeSuccess, nil, "")
	if err := s.persistLocked(ctx); err != nil {
		s.mu.Unlock()
		return protocol.RetireResponse{}, err
	}
	s.mu.Unlock()
	// Best-effort vault revocation: retirement must not leave a usable copy of
	// the credential in the selected vault or in the cluster μVault. The
	// provider identity is already decommissioned, so a vault failure
	// surfaces as an attention event only.
	if vault := s.vault(); vault != nil {
		s.revokeFromVault(ctx, identity, operator, now)
	}
	s.revokeFromCommonVault(ctx, identity, now)

	s.mu.Lock()
	events := s.eventsSnapshotLocked(identity.ID)
	s.mu.Unlock()
	return protocol.RetireResponse{APIVersion: protocol.Version, Identity: identity, Events: events}, nil
}

// Delete permanently removes a retired machine identity — the record, its
// audit events, and its rotation runs — from the control-plane store. It is
// the final decommissioning step: only retired identities can be deleted,
// explicit confirmation is required, and the operation cannot be undone.
// The response carries the identity as it stood at deletion plus the final
// audit snapshot (including the terminal identity.deleted event), so callers
// retain the evidence after the purge. Best-effort vault revocation runs
// first, so no usable credential copy outlives the record; revocation
// failures surface as attention events inside that final snapshot.
func (s *Store) Delete(ctx context.Context, req protocol.DeleteRequest, now time.Time) (protocol.DeleteResponse, error) {
	if !req.Confirm {
		return protocol.DeleteResponse{}, ErrConfirmationNeeded
	}
	s.mu.Lock()
	now = now.UTC()
	identity, ok := s.identities[req.ID]
	if !ok {
		s.mu.Unlock()
		return protocol.DeleteResponse{}, ErrNotFound
	}
	if identity.State != protocol.StateRetired {
		s.mu.Unlock()
		return protocol.DeleteResponse{}, fmt.Errorf("%w: %s", ErrNotRetired, identity.State)
	}
	s.mu.Unlock()

	// Retirement must already have revoked the vault copies; the delete
	// re-revokes best-effort so a failed retirement revocation cannot leave a
	// usable credential behind a purged record. Failures land in the final
	// audit snapshot below.
	if vault := s.vault(); vault != nil {
		s.revokeFromVault(ctx, identity, req.RequestedByOrDefault(), now)
	}
	s.revokeFromCommonVault(ctx, identity, now)

	s.mu.Lock()
	// A concurrent delete may have won the race; the record is already gone
	// and its evidence was returned to that caller.
	if _, stillThere := s.identities[req.ID]; !stillThere {
		s.mu.Unlock()
		return protocol.DeleteResponse{}, ErrNotFound
	}
	s.addEvent(identity.ID, now, protocol.EventIdentityDeleted,
		"Permanently deleted "+identity.Name+" and its audit trail from the control plane ("+req.Reason+")",
		req.RequestedByOrDefault(), protocol.OutcomeSuccess,
		map[string]string{"reason": req.Reason, "state": string(identity.State)}, "")
	events := s.eventsSnapshotLocked(identity.ID)
	delete(s.identities, identity.ID)
	delete(s.events, identity.ID)
	delete(s.runs, identity.ID)
	if err := s.persistLocked(ctx); err != nil {
		s.mu.Unlock()
		return protocol.DeleteResponse{}, err
	}
	s.mu.Unlock()
	return protocol.DeleteResponse{
		APIVersion: protocol.Version,
		Deleted:    true,
		Identity:   identity,
		Events:     events,
	}, nil
}

// revokeFromVault disables the vault copy of a retired credential and records
// the credential.revoked audit event.
func (s *Store) revokeFromVault(ctx context.Context, identity protocol.MachineIdentity, operator string, now time.Time) {
	vault := s.vault()
	if vault == nil {
		return
	}
	now = now.UTC()
	ref, err := vault.RevokeSecret(ctx, identity, identity.Credential.KeyID)
	if err != nil {
		if errors.Is(err, ErrVaultUnsupported) {
			return
		}
		s.mu.Lock()
		s.addEvent(identity.ID, now, protocol.EventCredentialRevoked,
			"Vault revocation failed: "+err.Error(), protocol.ActorProviderAdapter,
			protocol.OutcomeAttention,
			map[string]string{"key_id": identity.Credential.KeyID, "error": err.Error()}, "")
		s.mu.Unlock()
		return
	}
	details := map[string]string{
		"key_id":        identity.Credential.KeyID,
		"vault_secret":  ref.SecretName,
		"vault_version": ref.Version,
	}
	if ref.URL != "" {
		details["vault_url"] = ref.URL
	}
	s.mu.Lock()
	s.addEvent(identity.ID, now, protocol.EventCredentialRevoked,
		"Vault copy disabled in the "+providerVaultLabel(identity.Provider.Provider),
		protocol.ActorProviderAdapter, protocol.OutcomeSuccess, details, "")
	s.mu.Unlock()
}

// Use retrieves the current (or pinned) credential version of one governed
// identity from the selected provider-native vault and audits the retrieval as
// credential.used. The secret value is returned exactly once in the response
// and never persisted; retired identities no longer have a retrievable
// credential.
func (s *Store) Use(ctx context.Context, req protocol.UseRequest, now time.Time) (protocol.UseResponse, error) {
	identity, ok := s.Get(req.ID)
	if !ok {
		return protocol.UseResponse{}, ErrNotFound
	}
	if identity.State == protocol.StateRetired {
		return protocol.UseResponse{}, ErrAlreadyRetired
	}
	vault := s.vault()
	if vault == nil && s.commonVault == nil {
		return protocol.UseResponse{}, ErrVaultUnsupported
	}
	var (
		value     string
		ref       protocol.VaultReference
		nativeErr error
	)
	if vault != nil {
		value, ref, nativeErr = vault.ReadSecret(ctx, identity, identity.Credential.KeyID, req.Version)
	}
	fromClusterVault := false
	if nativeErr != nil || vault == nil {
		if vault != nil && !errors.Is(nativeErr, ErrVaultUnsupported) {
			// A native outage must not silently switch vaults: only an
			// intentionally unsupported native capability falls back.
			return protocol.UseResponse{}, fmt.Errorf("%w: %v", ErrProviderFailure, nativeErr)
		}
		if s.commonVault == nil {
			return protocol.UseResponse{}, fmt.Errorf("%w: %v", ErrProviderFailure, nativeErr)
		}
		// The provider-native vault cannot serve this read, so fall back to
		// the cluster μVault copy recorded at delivery time.
		var err error
		value, ref, err = s.commonVault.ReadSecret(ctx, identity, identity.Credential.KeyID, req.Version)
		if err != nil {
			return protocol.UseResponse{}, fmt.Errorf("%w: %v", ErrProviderFailure, err)
		}
		fromClusterVault = true
	}
	now = now.UTC()
	details := map[string]string{"key_id": identity.Credential.KeyID}
	summary := ""
	if fromClusterVault {
		details["vault_kind"] = commonVaultKind
		details["common_vault_secret"] = ref.SecretName
		if ref.Version != "" {
			details["common_vault_version"] = ref.Version
		}
		if ref.URL != "" {
			details["common_vault_url"] = ref.URL
		}
		summary = "Credential retrieved from the cluster μVault vault by " + req.RequestedByOrDefault()
	} else {
		details["vault_secret"] = ref.SecretName
		details["vault_version"] = ref.Version
		if ref.URL != "" {
			details["vault_url"] = ref.URL
		}
		summary = "Credential retrieved from the " + providerVaultLabel(identity.Provider.Provider) + " by " + req.RequestedByOrDefault()
	}
	s.mu.Lock()
	s.addEvent(identity.ID, now, protocol.EventCredentialUsed, summary,
		req.RequestedByOrDefault(), protocol.OutcomeSuccess, details, "")
	persistErr := s.persistLocked(ctx)
	s.mu.Unlock()
	if persistErr != nil {
		return protocol.UseResponse{}, persistErr
	}
	return protocol.UseResponse{
		APIVersion: protocol.Version,
		Identity:   identity,
		KeyID:      identity.Credential.KeyID,
		Secret:     value,
		Vault:      &ref,
	}, nil
}

// withVaultMetadata records the vault location of the current credential on
// the identity. Only names, URLs, and versions are stored — never secrets.
func withVaultMetadata(metadata protocol.Metadata, ref *protocol.VaultReference) protocol.Metadata {
	if ref == nil {
		return metadata
	}
	if metadata == nil {
		metadata = protocol.Metadata{}
	}
	if ref.URL != "" {
		metadata[metaVaultURL] = ref.URL
	}
	metadata[metaVaultSecret] = ref.SecretName
	if ref.Version != "" {
		metadata[metaVaultVersion] = ref.Version
	}
	return metadata
}

// withCommonVaultMetadata records the cluster μVault location of the current
// credential on the identity, leaving any provider-native vault keys intact:
// an identity mirrored to both vaults carries both key sets. Only names,
// URLs, and versions are stored — never secrets.
func withCommonVaultMetadata(metadata protocol.Metadata, ref *protocol.VaultReference) protocol.Metadata {
	if ref == nil {
		return metadata
	}
	if metadata == nil {
		metadata = protocol.Metadata{}
	}
	if ref.URL != "" {
		metadata[metaCommonVaultURL] = ref.URL
	}
	metadata[metaCommonVaultSecret] = ref.SecretName
	if ref.Version != "" {
		metadata[metaCommonVaultVersion] = ref.Version
	}
	return metadata
}

func (s *Store) eventsSnapshotLocked(id string) []protocol.LifecycleEvent {
	return append([]protocol.LifecycleEvent(nil), s.events[id]...)
}

// vault returns the adapter's vault delivery capability, or nil when the
// adapter cannot deliver credentials to a provider-native vault.
func (s *Store) vault() VaultStore {
	vault, _ := s.adapter.(VaultStore)
	return vault
}

// metaCommonVault* are the cluster μVault counterparts of the native vault
// metadata keys. They name the mirrored secret, version, and URL — never
// secret material — so consumers can distinguish the cluster copy from the
// provider-native copy.
const (
	metaCommonVaultURL     = "common_vault_url"
	metaCommonVaultSecret  = "common_vault_secret"
	metaCommonVaultVersion = "common_vault_version"
)

// commonVaultKind names the cluster μVault in audit event details.
const commonVaultKind = "cluster-mutandae-vault"

// vaultMetadataKeys are the provider-neutral identity metadata keys recording
// where the current credential lives. They name the vault, secret, and
// version — never secret material — so the inventory and API can display
// vault state and consumers can pin versions.
const (
	metaVaultURL     = "vault_url"
	metaVaultSecret  = "vault_secret"
	metaVaultVersion = "vault_version"
)

// deliverToVault stores a freshly issued credential in the selected
// provider-native vault, records the auditable credential.delivered event
// (success or failure), and updates the identity's vault metadata. It never
// fails the calling lifecycle operation: a vault outage is surfaced as an
// attention event while the identity itself remains governed.
func (s *Store) deliverToVault(ctx context.Context, identity protocol.MachineIdentity, keyID, secret string, now time.Time) *protocol.VaultReference {
	vault := s.vault()
	if vault == nil || strings.TrimSpace(secret) == "" {
		return nil
	}
	now = now.UTC()
	ref, err := vault.StoreSecret(ctx, identity, keyID, secret)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		// An intentionally absent vault capability is not a failure: it means
		// the operator disabled delivery (MUTANDAE_VAULT=off or no vault URL),
		// so the provision result simply reports no vault copy.
		if errors.Is(err, ErrVaultUnsupported) {
			return nil
		}
		s.addEvent(identity.ID, now, protocol.EventCredentialDelivered,
			"Vault delivery failed: the credential was issued but not stored in the "+providerVaultLabel(identity.Provider.Provider),
			protocol.ActorProviderAdapter, protocol.OutcomeAttention,
			map[string]string{"key_id": keyID, "error": err.Error(), "provider": identity.Provider.Provider}, "")
		return nil
	}
	details := map[string]string{
		"key_id":        keyID,
		"vault_secret":  ref.SecretName,
		"provider":      identity.Provider.Provider,
		"vault_version": ref.Version,
	}
	if ref.URL != "" {
		details["vault_url"] = ref.URL
	}
	s.addEvent(identity.ID, now, protocol.EventCredentialDelivered,
		"Credential stored in the "+providerVaultLabel(identity.Provider.Provider)+" ("+ref.SecretName+"), retrievable on demand",
		protocol.ActorProviderAdapter, protocol.OutcomeSuccess, details, "")
	return &ref
}

// mirrorToCommonVault stores a freshly issued credential in the cluster μVault
// and records its own credential.delivered audit event, independent of the
// provider-native delivery. It never fails the calling lifecycle operation: a
// mirror outage surfaces as an attention event while the identity remains
// governed, an intentionally unsupported μVault capability (like a disabled
// native vault) is silently skipped, and an unconfigured μVault does nothing.
func (s *Store) mirrorToCommonVault(ctx context.Context, identity protocol.MachineIdentity, keyID, secret string, now time.Time) *protocol.VaultReference {
	if s.commonVault == nil || strings.TrimSpace(secret) == "" {
		return nil
	}
	now = now.UTC()
	ref, err := s.commonVault.StoreSecret(ctx, identity, keyID, secret)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		if errors.Is(err, ErrVaultUnsupported) {
			return nil
		}
		s.addEvent(identity.ID, now, protocol.EventCredentialDelivered,
			"Cluster vault delivery failed: the credential was issued but not stored in the cluster μVault vault",
			protocol.ActorProviderAdapter, protocol.OutcomeAttention,
			map[string]string{"key_id": keyID, "vault_kind": commonVaultKind, "error": err.Error()}, "")
		return nil
	}
	details := map[string]string{
		"key_id":               keyID,
		"vault_kind":           commonVaultKind,
		"common_vault_secret":  ref.SecretName,
		"common_vault_version": ref.Version,
	}
	if ref.URL != "" {
		details["common_vault_url"] = ref.URL
	}
	s.addEvent(identity.ID, now, protocol.EventCredentialDelivered,
		"Credential stored in the cluster μVault vault ("+ref.SecretName+"), retrievable on demand",
		protocol.ActorProviderAdapter, protocol.OutcomeSuccess, details, "")
	return &ref
}

// revokeFromCommonVault disables the cluster μVault copy of a retired
// credential and records its own credential.revoked audit event, independent
// of the provider-native revocation. It is best-effort like the native path:
// a failure surfaces as an attention event, an unsupported capability is
// silently skipped, and an unconfigured μVault does nothing.
func (s *Store) revokeFromCommonVault(ctx context.Context, identity protocol.MachineIdentity, now time.Time) {
	if s.commonVault == nil {
		return
	}
	now = now.UTC()
	ref, err := s.commonVault.RevokeSecret(ctx, identity, identity.Credential.KeyID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		if errors.Is(err, ErrVaultUnsupported) {
			return
		}
		s.addEvent(identity.ID, now, protocol.EventCredentialRevoked,
			"Cluster vault revocation failed: "+err.Error(),
			protocol.ActorProviderAdapter, protocol.OutcomeAttention,
			map[string]string{"key_id": identity.Credential.KeyID, "vault_kind": commonVaultKind, "error": err.Error()}, "")
		return
	}
	details := map[string]string{
		"key_id":               identity.Credential.KeyID,
		"vault_kind":           commonVaultKind,
		"common_vault_secret":  ref.SecretName,
		"common_vault_version": ref.Version,
	}
	if ref.URL != "" {
		details["common_vault_url"] = ref.URL
	}
	s.addEvent(identity.ID, now, protocol.EventCredentialRevoked,
		"Cluster vault copy removed (μVault)",
		protocol.ActorProviderAdapter, protocol.OutcomeSuccess, details, "")
}

// providerVaultLabel names the provider-native vault in audit summaries.
func providerVaultLabel(provider string) string {
	switch provider {
	case "azure-entra":
		return "Azure Key Vault"
	case "aws-iam":
		return "AWS Secrets Manager"
	case "gcp-iam":
		return "GCP Secret Manager"
	default:
		return "provider vault"
	}
}

// Transition validates a lifecycle state change against the protocol's
// canonical state machine. It exists as a standalone guard for callers that
// reason about transitions directly.
func Transition(from, to protocol.State) error {
	if !protocol.CanTransition(from, to) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, from, to)
	}
	return nil
}
