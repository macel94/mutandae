package lifecycle

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

type sweepAdapter struct {
	mu          sync.Mutex
	discoveries []protocol.MachineIdentity
	failures    map[string]error
	rotated     []string
}

func (a *sweepAdapter) Kind() string { return "azure-entra" }

func (a *sweepAdapter) Discover(context.Context) ([]protocol.MachineIdentity, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]protocol.MachineIdentity(nil), a.discoveries...), nil
}

func (a *sweepAdapter) Rotate(_ context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rotated = append(a.rotated, identity.ID)
	if err := a.failures[identity.ID]; err != nil {
		return protocol.MachineIdentity{}, err
	}
	identity.Credential.KeyID = identity.ID + "-rotated"
	identity.Credential.Fingerprint = "sha256:rotated"
	return identity, nil
}

func (a *sweepAdapter) Retire(_ context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error) {
	identity.State = protocol.StateRetired
	return identity, nil
}

func (a *sweepAdapter) rotatedIDs() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.rotated...)
}

type sweepLease struct {
	acquire  bool
	mu       sync.Mutex
	tries    int
	releases int
	renews   int
}

func (l *sweepLease) TryAcquire(context.Context) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tries++
	return l.acquire, nil
}

func (l *sweepLease) Renew(context.Context) error {
	l.mu.Lock()
	l.renews++
	l.mu.Unlock()
	return nil
}

func (l *sweepLease) Release(context.Context) error {
	l.mu.Lock()
	l.releases++
	l.mu.Unlock()
	return nil
}

func (*sweepLease) LeaseRenewInterval() time.Duration { return 0 }

func sweepIdentity(id string, expiry time.Time) protocol.MachineIdentity {
	return protocol.MachineIdentity{
		ID: id, Name: id,
		Provider:   protocol.ProviderBinding{Provider: "azure-entra", ProviderID: id + "-provider"},
		Ownership:  protocol.Ownership{Team: "Platform", Service: id, Purpose: "sweep", Criticality: "medium"},
		Policy:     protocol.LifecyclePolicy{RenewalPeriod: "P90D"},
		Credential: protocol.CredentialReference{Kind: "client_secret", KeyID: id + "-key"},
		ExpiresAt:  expiry, State: protocol.StateActive, Health: protocol.HealthHealthy,
	}
}

func newSweepTestStore(t *testing.T, adapter Adapter) *Store {
	t.Helper()
	store, err := NewStore(context.Background(), now(), adapter)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestSweeperRotatesExactlyOverdueActiveIdentities(t *testing.T) {
	current := now()
	adapter := &sweepAdapter{discoveries: []protocol.MachineIdentity{
		sweepIdentity("overdue", current.Add(-time.Hour)),
		sweepIdentity("healthy", current.Add(45*24*time.Hour)),
		sweepIdentity("expiring", current.Add(10*24*time.Hour)),
		sweepIdentity("retired", current.Add(-2*time.Hour)),
	}, failures: map[string]error{}}
	store := newSweepTestStore(t, adapter)
	if _, err := store.Retire(context.Background(), protocol.RetireRequest{ID: "retired", Confirm: true}, current); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	lease := &sweepLease{acquire: true}
	sweeper, err := NewSweeper(SweeperConfig{Store: store, Clock: func() time.Time { return current }, Interval: time.Hour, Lease: lease})
	if err != nil {
		t.Fatalf("NewSweeper: %v", err)
	}
	result, err := sweeper.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if !result.Leader || result.Considered != 1 || result.Rotated != 1 || len(result.Failures) != 0 {
		t.Fatalf("result = %+v, want one successful overdue rotation", result)
	}
	rotated := adapter.rotatedIDs()
	if len(rotated) != 1 || rotated[0] != "overdue" {
		t.Fatalf("rotated identities = %v, want [overdue]", rotated)
	}
	for _, id := range []string{"healthy", "expiring", "retired"} {
		for _, rotatedID := range rotated {
			if rotatedID == id {
				t.Errorf("%s was rotated unexpectedly", id)
			}
		}
	}
	events, _ := store.Events("overdue")
	var started, completed *protocol.LifecycleEvent
	for index := range events {
		switch events[index].Type {
		case protocol.EventRotationStarted:
			copy := events[index]
			started = &copy
		case protocol.EventRotationCompleted:
			copy := events[index]
			completed = &copy
		}
	}
	if started == nil || completed == nil {
		t.Fatalf("events = %+v, want started and completed", events)
	}
	if started.Actor != "system:sweeper" || completed.Actor != "system:sweeper" {
		t.Fatalf("sweeper event actors = %q/%q, want system:sweeper", started.Actor, completed.Actor)
	}
	if started.CorrelationID == "" || started.CorrelationID != completed.CorrelationID || started.RunID != completed.RunID {
		t.Fatalf("event correlation = started(%q,%q), completed(%q,%q)", started.CorrelationID, started.RunID, completed.CorrelationID, completed.RunID)
	}
}

func TestSweeperFailureBackoffDoesNotBlockOtherIdentities(t *testing.T) {
	current := now()
	failure := errors.New("provider unavailable")
	adapter := &sweepAdapter{
		discoveries: []protocol.MachineIdentity{
			sweepIdentity("fails", current.Add(-time.Hour)),
			sweepIdentity("works", current.Add(-2*time.Hour)),
		},
		failures: map[string]error{"fails": failure},
	}
	store := newSweepTestStore(t, adapter)
	sweeper, err := NewSweeper(SweeperConfig{Store: store, Clock: func() time.Time { return current }, Interval: time.Hour, Lease: &sweepLease{acquire: true}})
	if err != nil {
		t.Fatalf("NewSweeper: %v", err)
	}
	first, err := sweeper.Sweep(context.Background())
	if err != nil {
		t.Fatalf("first Sweep: %v", err)
	}
	if first.Considered != 2 || first.Rotated != 1 || len(first.Failures) != 1 || first.Failures[0].IdentityID != "fails" {
		t.Fatalf("first result = %+v, want one failure and one success", first)
	}
	second, err := sweeper.Sweep(context.Background())
	if err != nil {
		t.Fatalf("second Sweep: %v", err)
	}
	if second.Considered != 0 || len(adapter.rotatedIDs()) != 2 {
		t.Fatalf("immediate retry result = %+v, calls = %v; want backoff", second, adapter.rotatedIDs())
	}
	current = current.Add(time.Hour / 4)
	third, err := sweeper.Sweep(context.Background())
	if err != nil {
		t.Fatalf("third Sweep: %v", err)
	}
	if third.Considered != 1 || len(third.Failures) != 1 || third.Failures[0].IdentityID != "fails" {
		t.Fatalf("backoff retry result = %+v, want failed identity retried", third)
	}
}

func TestSweeperOnlyLeaderRuns(t *testing.T) {
	current := now()
	adapter := &sweepAdapter{discoveries: []protocol.MachineIdentity{sweepIdentity("overdue", current.Add(-time.Hour))}, failures: map[string]error{}}
	store := newSweepTestStore(t, adapter)
	lease := &sweepLease{acquire: false}
	sweeper, err := NewSweeper(SweeperConfig{Store: store, Clock: func() time.Time { return current }, Interval: time.Hour, Lease: lease})
	if err != nil {
		t.Fatalf("NewSweeper: %v", err)
	}
	result, err := sweeper.Sweep(context.Background())
	if err != nil {
		t.Fatalf("non-leader Sweep: %v", err)
	}
	if result.Leader || len(adapter.rotatedIDs()) != 0 || lease.releases != 0 {
		t.Fatalf("non-leader result = %+v, rotations = %v, releases = %d", result, adapter.rotatedIDs(), lease.releases)
	}
}

func TestSweeperJitterBounds(t *testing.T) {
	current := now()
	store := newSweepTestStore(t, &sweepAdapter{failures: map[string]error{}})
	for _, test := range []struct {
		name   string
		random float64
		want   time.Duration
	}{
		{name: "lower", random: 0, want: time.Hour},
		{name: "upper", random: 1, want: time.Hour + 10*time.Minute},
		{name: "clamp low", random: -1, want: time.Hour},
		{name: "clamp high", random: 2, want: time.Hour + 10*time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			sweeper, err := NewSweeper(SweeperConfig{Store: store, Clock: func() time.Time { return current }, Interval: time.Hour, Jitter: 10 * time.Minute, Random: func() float64 { return test.random }})
			if err != nil {
				t.Fatalf("NewSweeper: %v", err)
			}
			if got := sweeper.nextDelay(); got != test.want {
				t.Fatalf("nextDelay = %s, want %s", got, test.want)
			}
		})
	}
}

type manualTicker struct {
	channel chan time.Time
	mu      sync.Mutex
	stopped bool
}

func (t *manualTicker) C() <-chan time.Time { return t.channel }
func (t *manualTicker) Stop() {
	t.mu.Lock()
	t.stopped = true
	t.mu.Unlock()
}

func TestSweeperRunUsesInjectedTickerAndStopsPromptly(t *testing.T) {
	current := now()
	store := newSweepTestStore(t, &sweepAdapter{failures: map[string]error{}})
	lease := &sweepLease{acquire: true}
	created := make(chan *manualTicker, 4)
	sweeper, err := NewSweeper(SweeperConfig{
		Store: store, Clock: func() time.Time { return current }, Interval: time.Hour, Jitter: 10 * time.Minute,
		Lease: lease, Random: func() float64 { return 0.5 },
		NewTicker: func(duration time.Duration) Ticker {
			if duration != time.Hour+5*time.Minute {
				t.Errorf("ticker duration = %s, want 1h5m", duration)
			}
			ticker := &manualTicker{channel: make(chan time.Time, 1)}
			created <- ticker
			return ticker
		},
	})
	if err != nil {
		t.Fatalf("NewSweeper: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sweeper.Run(ctx) }()
	first := <-created
	first.channel <- current
	second := <-created
	if second == nil {
		t.Fatal("worker did not schedule the next interval")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not stop promptly after cancellation")
	}
	if lease.releases != 1 {
		t.Fatalf("lease releases = %d, want 1", lease.releases)
	}
}
