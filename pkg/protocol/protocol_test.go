package protocol

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestISO8601DurationRoundTrip(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{90 * 24 * time.Hour, "P90D"},
		{7 * 24 * time.Hour, "P7D"},
		{6 * time.Hour, "PT6H"},
		{24*time.Hour + 6*time.Hour, "P1DT6H"},
		{45 * time.Minute, "PT45M"},
		{12 * time.Second, "PT12S"},
		{time.Second + 500*time.Millisecond, "PT1.500S"},
		{0, "P0D"},
		{2*time.Hour + 30*time.Minute + 45*time.Second, "PT2H30M45S"},
	}
	for _, tc := range cases {
		got := FormatISO8601Duration(tc.in)
		if got != tc.want {
			t.Errorf("FormatISO8601Duration(%v) = %q, want %q", tc.in, got, tc.want)
		}
		parsed, err := ParseISO8601Duration(got)
		if err != nil {
			t.Fatalf("ParseISO8601Duration(%q): %v", got, err)
		}
		// Sub-second rounding only affects durations that include milliseconds.
		if got2 := FormatISO8601Duration(parsed); got2 != got {
			t.Errorf("round-trip parse of %q = %q, want %q", got, got2, got)
		}
	}
}

func TestParseISO8601Duration(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"P90D", 90 * 24 * time.Hour, true},
		{"P1W", 7 * 24 * time.Hour, true},
		{"PT6h", 6 * time.Hour, false}, // lowercase is not supported
		{"PT6H", 6 * time.Hour, true},
		{"PT6H30M", 6*time.Hour + 30*time.Minute, true},
		{"PT1M30S", time.Minute + 30*time.Second, true},
		{"P1DT12H", 24*time.Hour + 12*time.Hour, true},
		{"P", 0, false},
		{"", 0, false},
		{"D90", 0, false},
		{"P1M", 0, false}, // months unsupported
		{"P6H", 0, false}, // time designator required
		{"PT", 0, false},
	}
	for _, tc := range cases {
		got, err := ParseISO8601Duration(tc.in)
		if tc.ok != (err == nil) {
			t.Errorf("ParseISO8601Duration(%q) error = %v, want ok = %v", tc.in, err, tc.ok)
			continue
		}
		if tc.ok && got != tc.want {
			t.Errorf("ParseISO8601Duration(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestCanTransition(t *testing.T) {
	cases := []struct {
		from State
		to   State
		want bool
	}{
		{StateRegistered, StateActive, true},
		{StateActive, StateRenewing, true},
		{StateRenewing, StateActive, true},
		{StateActive, StateRetired, true},
		{StateRenewing, StateRetired, true},
		{StateRetired, StateActive, false},
		{StateRegistered, StateRetired, false},
		{State("bogus"), StateActive, false},
	}
	for _, tc := range cases {
		if got := CanTransition(tc.from, tc.to); got != tc.want {
			t.Errorf("CanTransition(%q, %q) = %v, want %v", tc.from, tc.to, got, tc.want)
		}
	}
}

func validIdentity() MachineIdentity {
	return MachineIdentity{
		ID:   "payments-api",
		Name: "payments-api",
		Provider: ProviderBinding{
			Provider: "azure-entra", ProviderID: "abc", TenantID: "tenant-1", ObjectID: "obj-1",
		},
		Ownership: Ownership{Team: "Payments", Service: "authz", Purpose: "payment authorization", Criticality: "critical", Contacts: []string{"payments@example.test"}},
		Policy:    LifecyclePolicy{RenewalPeriod: "P90D", ApprovalRequired: false},
		Credential: CredentialReference{
			Kind: "client_secret", Location: "keyvault://vault/secrets/payments", Fingerprint: "sha256:abcd", KeyID: "key-1",
		},
		State: StateActive, Health: HealthHealthy,
		ExpiresAt: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC),
	}
}

func TestValidateIdentity(t *testing.T) {
	base := validIdentity()
	if err := ValidateIdentity(&base); err != nil {
		t.Fatalf("valid identity failed: %v", err)
	}

	cases := map[string]func(*MachineIdentity){
		"nil":                    func(_ *MachineIdentity) {},
		"missing id":             func(v *MachineIdentity) { v.ID = "" },
		"missing name":           func(v *MachineIdentity) { v.Name = "" },
		"missing provider":       func(v *MachineIdentity) { v.Provider.Provider = "" },
		"missing provider_id":    func(v *MachineIdentity) { v.Provider.ProviderID = "" },
		"missing ownership team": func(v *MachineIdentity) { v.Ownership.Team = "" },
		"missing ownership svc":  func(v *MachineIdentity) { v.Ownership.Service = "" },
		"invalid state":          func(v *MachineIdentity) { v.State = "bogus" },
		"invalid health":         func(v *MachineIdentity) { v.Health = "bogus" },
		"invalid renewal period": func(v *MachineIdentity) { v.Policy.RenewalPeriod = "weekly" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if name == "nil" {
				if err := ValidateIdentity(nil); !errors.Is(err, ErrConformance) {
					t.Fatalf("nil error = %v, want ErrConformance", err)
				}
				return
			}
			v := validIdentity()
			mutate(&v)
			err := ValidateIdentity(&v)
			if !errors.Is(err, ErrConformance) {
				t.Fatalf("error = %v, want ErrConformance", err)
			}
			var multi ValidationErrors
			if errors.As(err, &multi) && len(multi) == 0 {
				t.Fatalf("expected at least one validation message, got empty")
			}
		})
	}
}

func TestValidateEventAndRotationRun(t *testing.T) {
	ev := LifecycleEvent{
		ID: "evt-1", IdentityID: "payments-api", Type: EventRotationCompleted,
		Summary: "done", Actor: ActorProviderAdapter, Outcome: OutcomeSuccess,
		At: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC),
	}
	if err := ValidateEvent(&ev); err != nil {
		t.Fatalf("valid event failed: %v", err)
	}
	bad := ev
	bad.Outcome = "bogus"
	if !errors.Is(ValidateEvent(&bad), ErrConformance) {
		t.Fatal("invalid outcome not rejected")
	}

	run := RotationRun{ID: "run-1", IdentityID: "payments-api", Status: RotationRunning}
	if err := ValidateRotationRun(&run); err != nil {
		t.Fatalf("valid run failed: %v", err)
	}
	badRun := run
	badRun.Status = "zzz"
	if !errors.Is(ValidateRotationRun(&badRun), ErrConformance) {
		t.Fatal("invalid run status not rejected")
	}
}

func TestEnvelopeJSONRoundTrip(t *testing.T) {
	identity := validIdentity()
	resp := ListResponse{APIVersion: Version, Total: 1, Identities: []MachineIdentity{identity}}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded ListResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.APIVersion != Version {
		t.Fatalf("api_version = %q, want %q", decoded.APIVersion, Version)
	}
	if len(decoded.Identities) != 1 || !reflect.DeepEqual(decoded.Identities[0], identity) {
		t.Fatalf("identities not preserved over JSON: got %+v", decoded.Identities)
	}
	if err := ValidateIdentity(&decoded.Identities[0]); err != nil {
		t.Fatalf("decoded identity not conformant: %v", err)
	}
}

func TestFailureHelper(t *testing.T) {
	resp := Failure(NewError(ErrCodeInvalidTransition, "boom"))
	if resp.APIVersion != Version || resp.Error.Code != ErrCodeInvalidTransition {
		t.Fatalf("wrong failure envelope: %+v", resp)
	}
}
