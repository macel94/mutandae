package provider

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

func TestScopeMatchUsesFnmatchPatternsAndDenyWins(t *testing.T) {
	scope := Scope{
		Allow: []string{"mutandae-demo-*", "worker-?", "[a-z]-service"},
		Deny:  []string{"mutandae-demo-secret", "worker-x"},
	}
	for _, test := range []struct {
		name string
		want bool
	}{
		{"mutandae-demo-orders", true},
		{"mutandae-demo-secret", false},
		{"worker-a", true},
		{"worker-x", false},
		{"a-service", true},
		{"ab-service", false},
		{"production-user", false},
	} {
		if got := scope.Match(test.name); got != test.want {
			t.Errorf("Match(%q) = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestScopeEmptyAllowAndPatternValidation(t *testing.T) {
	if !(Scope{}).Match("any-name") {
		t.Fatal("empty Allow must match when Scope is evaluated directly")
	}
	if (Scope{Deny: []string{"private-*"}}).Match("private-key") {
		t.Fatal("Deny must win when Allow is empty")
	}
	if _, err := ParseScope("mutandae-demo-*, !mutandae-demo-secret"); err != nil {
		t.Fatalf("ParseScope() error = %v", err)
	}
	if _, err := ParseScope("["); err == nil {
		t.Fatal("ParseScope accepted an invalid path.Match pattern")
	}
	if err := (Scope{Allow: []string{""}}).Validate(); err == nil {
		t.Fatal("Validate accepted an empty pattern")
	}
}

func TestSimulatorExplicitZeroScopeDefaultsToDemoNamespace(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name     string
		discover func() ([]protocol.MachineIdentity, error)
	}{
		{name: "azure", discover: func() ([]protocol.MachineIdentity, error) {
			return NewSimulator("tenant", now, Scope{}).Discover(context.Background())
		}},
		{name: "aws", discover: func() ([]protocol.MachineIdentity, error) {
			return NewAWSSimulator("123456789012", "us-east-1", now, Scope{}).Discover(context.Background())
		}},
		{name: "gcp", discover: func() ([]protocol.MachineIdentity, error) {
			return NewGCPSimulator("project", "us-central1", now, Scope{}).Discover(context.Background())
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			identities, err := test.discover()
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if len(identities) == 0 {
				t.Fatal("demo-scoped simulator discovered no seeded identities")
			}
			for _, identity := range identities {
				if !strings.HasPrefix(identity.Name, DemoScopePattern[:len(DemoScopePattern)-1]) {
					t.Errorf("identity %q escaped the default demo namespace", identity.Name)
				}
			}
		})
	}
}

func TestScopeForbiddenErrorsUseProtocolSentinel(t *testing.T) {
	err := forbiddenScopeError("aws-iam", "production-user", DemoScope())
	if !errors.Is(err, protocol.ErrForbidden) {
		t.Fatalf("error = %v, want protocol.ErrForbidden", err)
	}
	if !strings.Contains(err.Error(), DemoScopePattern) {
		t.Fatalf("error = %v, want configured pattern", err)
	}
}

func TestSimulatorMutationsRejectOutOfScopeTargetsBeforeLookup(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		rotate func(protocol.MachineIdentity) error
		retire func(protocol.MachineIdentity) error
	}{
		{
			name: "azure",
			rotate: func(identity protocol.MachineIdentity) error {
				_, err := NewSimulator("tenant", now, DemoScope()).Rotate(context.Background(), identity)
				return err
			},
			retire: func(identity protocol.MachineIdentity) error {
				_, err := NewSimulator("tenant", now, DemoScope()).Retire(context.Background(), identity)
				return err
			},
		},
		{
			name: "aws",
			rotate: func(identity protocol.MachineIdentity) error {
				_, err := NewAWSSimulator("account", "us-east-1", now, DemoScope()).Rotate(context.Background(), identity)
				return err
			},
			retire: func(identity protocol.MachineIdentity) error {
				_, err := NewAWSSimulator("account", "us-east-1", now, DemoScope()).Retire(context.Background(), identity)
				return err
			},
		},
		{
			name: "gcp",
			rotate: func(identity protocol.MachineIdentity) error {
				_, err := NewGCPSimulator("project", "us-central1", now, DemoScope()).Rotate(context.Background(), identity)
				return err
			},
			retire: func(identity protocol.MachineIdentity) error {
				_, err := NewGCPSimulator("project", "us-central1", now, DemoScope()).Retire(context.Background(), identity)
				return err
			},
		},
	}
	identity := protocol.MachineIdentity{
		Name:     "production-user",
		Provider: protocol.ProviderBinding{ProviderID: "unknown-provider-id"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			for operation, call := range map[string]func(protocol.MachineIdentity) error{
				"rotate": testCase.rotate,
				"retire": testCase.retire,
			} {
				if err := call(identity); !errors.Is(err, protocol.ErrForbidden) {
					t.Errorf("%s error = %v, want protocol.ErrForbidden", operation, err)
				}
			}
		})
	}
}
