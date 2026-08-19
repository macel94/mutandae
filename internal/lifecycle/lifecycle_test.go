package lifecycle

import (
	"errors"
	"testing"
	"time"
)

func TestTransition(t *testing.T) {
	tests := []struct {
		name string
		from State
		to   State
		want bool
	}{
		{name: "registration activates", from: StateRegistered, to: StateActive, want: true},
		{name: "active renews", from: StateActive, to: StateRenewing, want: true},
		{name: "renewing activates", from: StateRenewing, to: StateActive, want: true},
		{name: "active retires", from: StateActive, to: StateRetired, want: true},
		{name: "retired cannot activate", from: StateRetired, to: StateActive, want: false},
		{name: "registered cannot retire", from: StateRegistered, to: StateRetired, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Transition(tt.from, tt.to)
			if (err == nil) != tt.want {
				t.Fatalf("Transition(%q, %q) error = %v, want valid = %v", tt.from, tt.to, err, tt.want)
			}
		})
	}
}

func TestRotateExtendsExpiryAndAudits(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	store := NewDemoStore(now)

	before, ok := store.Get("payments-api")
	if !ok {
		t.Fatal("payments-api was not seeded")
	}
	rotated, err := store.Rotate("payments-api", now)
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if rotated.State != StateActive {
		t.Fatalf("state = %q, want %q", rotated.State, StateActive)
	}
	if rotated.RenewalHealth != RenewalHealthy {
		t.Fatalf("renewal health = %q, want %q", rotated.RenewalHealth, RenewalHealthy)
	}
	if !rotated.ExpiresAt.After(before.ExpiresAt) {
		t.Fatalf("expiry = %v, want after previous expiry %v", rotated.ExpiresAt, before.ExpiresAt)
	}
	if !rotated.LastRotatedAt.Equal(now) {
		t.Fatalf("last rotated = %v, want %v", rotated.LastRotatedAt, now)
	}

	events, ok := store.Events("payments-api")
	if !ok || len(events) < 3 {
		t.Fatalf("events = %#v, want seed plus two rotation events", events)
	}
	if events[0].Type != "rotation.completed" || events[0].Outcome != "success" {
		t.Fatalf("latest event = %#v, want successful completion", events[0])
	}
	if events[1].Type != "rotation.started" {
		t.Fatalf("second event = %#v, want rotation.started", events[1])
	}
}

func TestRotateRejectsMissingAndRetiredIdentities(t *testing.T) {
	store := NewDemoStore(time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC))
	if _, err := store.Rotate("missing", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing error = %v, want ErrNotFound", err)
	}

	identity, ok := store.Get("inventory-sync")
	if !ok {
		t.Fatal("inventory-sync was not seeded")
	}
	if err := Transition(identity.State, StateRetired); err != nil {
		t.Fatalf("retire transition error = %v", err)
	}
	// The store intentionally exposes transition rules separately; this test
	// uses a fresh demo identity to verify the operation's terminal guard below.
	identity.State = StateRetired
	retiredStore := &Store{identities: map[string]Identity{identity.ID: identity}, events: map[string][]Event{}}
	if _, err := retiredStore.Rotate(identity.ID, time.Now()); !errors.Is(err, ErrAlreadyRetired) {
		t.Fatalf("retired error = %v, want ErrAlreadyRetired", err)
	}
}

func TestUrgency(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		expires time.Time
		state   State
		want    Urgency
	}{
		{name: "overdue", expires: now.Add(-time.Minute), state: StateActive, want: UrgencyOverdue},
		{name: "expiring", expires: now.Add(29 * 24 * time.Hour), state: StateActive, want: UrgencyExpiring},
		{name: "healthy", expires: now.Add(30 * 24 * time.Hour), state: StateActive, want: UrgencyHealthy},
		{name: "retired", expires: now.Add(-time.Hour), state: StateRetired, want: UrgencyRetired},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			identity := Identity{State: tt.state, ExpiresAt: tt.expires}
			if got := identity.Urgency(now); got != tt.want {
				t.Fatalf("Urgency() = %q, want %q", got, tt.want)
			}
		})
	}
}
