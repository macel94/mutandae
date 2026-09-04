package protocol

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// wireFixture is a fully-populated identity used by the envelope round-trip
// tests. Every string field is synthetic; nothing here is real credential
// material.
func wireFixture() MachineIdentity {
	return MachineIdentity{
		ID:          "identity-1",
		Name:        "mutandae-demo-fixture",
		DisplayName: "Fixture Identity",
		Namespace:   "mutandae-demo",
		Environment: "production",
		Provider: ProviderBinding{
			Provider: "aws-iam", ProviderID: "AIDEXAMPLE", TenantID: "",
			Region: "us-east-1", AccountID: "123456789012",
		},
		Ownership: Ownership{
			Team: "Platform", Service: "deploy", Purpose: "demo", Criticality: "high",
			Contacts: []string{"team@example.com"},
		},
		Policy:        LifecyclePolicy{RenewalPeriod: "P90D", GracePeriod: "P7D", MaxAge: "P1Y", ApprovalRequired: true},
		Credential:    CredentialReference{Kind: "access_key", Location: "iam", Fingerprint: "sha256:abc", KeyID: "AKIAEXAMPLE", Delivery: "secret-manager"},
		State:         StateActive,
		Health:        HealthHealthy,
		ExpiresAt:     time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
		LastRotatedAt: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC),
		CreatedAt:     time.Date(2026, 6, 4, 8, 0, 0, 0, time.UTC),
		UpdatedAt:     time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC),
		Metadata:      Metadata{"vault_version": "v1"},
	}
}

// roundTrip marshals and unmarshals a value, failing the test on either error
// or on any JSON key that does not use the protocol's snake_case convention.
func roundTrip(t *testing.T, value any, target any) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %T: %v", value, err)
	}
	for _, key := range camelCaseKeys(t, payload) {
		t.Errorf("field name %q violates the protocol's snake_case convention", key)
	}
	if err := json.Unmarshal(payload, target); err != nil {
		t.Fatalf("unmarshal %T: %v\npayload: %s", target, err, payload)
	}
}

// camelCaseKeys finds any top-level JSON object key containing an uppercase
// ASCII letter. The protocol mandates snake_case on the wire; this catches
// struct tags that silently drifted.
func camelCaseKeys(t *testing.T, payload []byte) []string {
	t.Helper()
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(payload, &generic); err != nil {
		return nil // arrays and scalars carry no keys
	}
	var offenders []string
	for key := range generic {
		for _, r := range key {
			if r >= 'A' && r <= 'Z' {
				offenders = append(offenders, key)
				break
			}
		}
	}
	return offenders
}

func TestLifecycleEnvelopeRoundTrips(t *testing.T) {
	t.Parallel()
	fixture := wireFixture()
	fixed := time.Date(2026, 9, 2, 15, 0, 0, 0, time.UTC)
	secret := "one-time-secret-value"

	identityJSON, err := json.Marshal(fixture)
	if err != nil {
		t.Fatalf("marshal identity: %v", err)
	}

	t.Run("ListResponse", func(t *testing.T) {
		in := ListResponse{APIVersion: Version, Total: 1, Identities: []MachineIdentity{fixture}}
		var out ListResponse
		roundTrip(t, &in, &out)
		if out.APIVersion != Version || out.Total != 1 || len(out.Identities) != 1 || out.Identities[0].Name != fixture.Name {
			t.Fatalf("round trip lost data: %+v", out)
		}
	})

	t.Run("InspectResponse", func(t *testing.T) {
		in := InspectResponse{APIVersion: Version, Identity: fixture}
		var out InspectResponse
		roundTrip(t, &in, &out)
		if out.Identity.ID != fixture.ID || out.Identity.ExpiresAt != fixture.ExpiresAt {
			t.Fatalf("identity did not survive the round trip: %+v", out.Identity)
		}
	})

	t.Run("RegisterRequestAndResponse", func(t *testing.T) {
		in := RegisterRequest{
			Name: "mutandae-demo-fixture", Provider: fixture.Provider, Ownership: fixture.Ownership,
			Policy: fixture.Policy, RequestedBy: "tester",
		}
		var outReq RegisterRequest
		roundTrip(t, &in, &outReq)
		if outReq.Name != in.Name || outReq.Provider.ProviderID != in.Provider.ProviderID {
			t.Fatalf("register request round trip lost data: %+v", outReq)
		}
		var events []LifecycleEvent
		if err := json.Unmarshal(identityJSON, &fixture); err != nil {
			t.Fatalf("identity fixture: %v", err)
		}
		events = append(events, LifecycleEvent{
			ID: "evt-1", IdentityID: fixture.ID, Type: EventIdentityRegistered, Summary: "registered",
			Actor: ActorControlPlane, Outcome: OutcomeSuccess, At: fixed,
		})
		inResp := RegisterResponse{APIVersion: Version, Identity: fixture, Events: events}
		var outResp RegisterResponse
		roundTrip(t, &inResp, &outResp)
		if len(outResp.Events) != 1 || outResp.Events[0].Type != EventIdentityRegistered {
			t.Fatalf("register response events lost: %+v", outResp.Events)
		}
	})

	t.Run("RotateRequestAndResponse", func(t *testing.T) {
		in := RotateRequest{ID: fixture.ID, RequestedBy: "tester", Reason: "policy"}
		var outReq RotateRequest
		roundTrip(t, &in, &outReq)
		if outReq.ID != in.ID || outReq.RequestedByOrDefault() != "tester" {
			t.Fatalf("rotate request round trip lost data: %+v", outReq)
		}
		inResp := RotateResponse{
			APIVersion: Version, Identity: fixture,
			Rotation: RotationRun{ID: "run-1", IdentityID: fixture.ID, Status: RotationSucceeded, RequestedAt: fixed, Outcome: OutcomeSuccess},
			Events:   nil,
		}
		var outResp RotateResponse
		roundTrip(t, &inResp, &outResp)
		if outResp.Rotation.Status != RotationSucceeded {
			t.Fatalf("rotation run lost: %+v", outResp.Rotation)
		}
	})

	t.Run("RetireRequestAndResponse", func(t *testing.T) {
		in := RetireRequest{ID: fixture.ID, Confirm: true, Reason: "offboard"}
		var outReq RetireRequest
		roundTrip(t, &in, &outReq)
		if !outReq.Confirm || outReq.ID != in.ID {
			t.Fatalf("retire request round trip lost data: %+v", outReq)
		}
		inResp := RetireResponse{APIVersion: Version, Identity: fixture}
		var outResp RetireResponse
		roundTrip(t, &inResp, &outResp)
		if outResp.Identity.State != StateActive {
			t.Fatalf("retire response identity lost: %+v", outResp.Identity)
		}
	})

	t.Run("ProvisionRequestNeverSerializesOwnerIP", func(t *testing.T) {
		in := ProvisionRequest{Provider: "aws-iam", Purpose: "demo", RequestedBy: "visitor", OwnerIP: "203.0.113.7"}
		payload, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("marshal provision request: %v", err)
		}
		if strings.Contains(string(payload), "203.0.113.7") {
			t.Fatalf("ProvisionRequest leaked OwnerIP onto the wire: %s", payload)
		}
		if strings.Contains(string(payload), "owner_ip") {
			t.Fatalf("ProvisionRequest serialized an owner_ip field: %s", payload)
		}
		var out ProvisionRequest
		if err := json.Unmarshal(payload, &out); err != nil {
			t.Fatalf("unmarshal provision request: %v", err)
		}
		if out.Provider != "aws-iam" || out.Purpose != "demo" {
			t.Fatalf("provision request lost data: %+v", out)
		}
		if out.OwnerIP != "" {
			t.Fatalf("OwnerIP must not survive a wire round trip, got %q", out.OwnerIP)
		}
	})

	t.Run("ProvisionResponseCarriesOneTimeSecretAndVaultReference", func(t *testing.T) {
		in := ProvisionResponse{
			APIVersion: Version, Identity: fixture, OneTimeSecret: secret, KeyID: "AKIAEXAMPLE",
			Instructions: "copy it now",
			Vault:        &VaultReference{URL: "https://vault.example", SecretName: "mutandae/demo/fixture", Version: "v1"},
		}
		var out ProvisionResponse
		roundTrip(t, &in, &out)
		if out.OneTimeSecret != secret {
			t.Fatalf("one-time secret lost: %q", out.OneTimeSecret)
		}
		if out.Vault == nil || out.Vault.SecretName != "mutandae/demo/fixture" {
			t.Fatalf("vault reference lost: %+v", out.Vault)
		}
	})

	t.Run("UseRequestAndResponse", func(t *testing.T) {
		in := UseRequest{ID: fixture.ID, RequestedBy: "visitor", Version: "v2"}
		var outReq UseRequest
		roundTrip(t, &in, &outReq)
		if outReq.Version != "v2" || outReq.RequestedByOrDefault() != "visitor" {
			t.Fatalf("use request round trip lost data: %+v", outReq)
		}
		inResp := UseResponse{
			APIVersion: Version, Identity: fixture, KeyID: "AKIAEXAMPLE", Secret: secret,
			Vault: &VaultReference{URL: "https://vault.example", SecretName: "mutandae/demo/fixture", Version: "v2"},
		}
		var outResp UseResponse
		roundTrip(t, &inResp, &outResp)
		if outResp.Secret != secret {
			t.Fatalf("use response secret lost: %q", outResp.Secret)
		}
	})

	t.Run("UseResponseOmitsSecretWhenEmpty", func(t *testing.T) {
		payload, err := json.Marshal(UseResponse{APIVersion: Version, Identity: fixture})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var generic map[string]json.RawMessage
		if err := json.Unmarshal(payload, &generic); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if _, ok := generic["secret"]; ok {
			t.Fatalf("empty use response must omit the secret key: %s", payload)
		}
	})

	t.Run("VaultReferenceHasNoSecretMaterialField", func(t *testing.T) {
		payload, err := json.Marshal(VaultReference{URL: "https://vault.example", SecretName: "n", Version: "v1"})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		for _, forbidden := range []string{"secret_value", "secret_text", "value", "password"} {
			var generic map[string]json.RawMessage
			_ = json.Unmarshal(payload, &generic)
			if _, ok := generic[forbidden]; ok {
				t.Errorf("VaultReference serialized forbidden key %q", forbidden)
			}
		}
	})

	t.Run("ConfigurationResponse", func(t *testing.T) {
		in := ConfigurationResponse{APIVersion: Version, Configuration: Configuration{
			Service: "mutandae", ProtocolVersion: Version, MediaType: MediaType, Environment: "live",
			Provider: "multi-cloud", Persistence: "redis", ReadOnly: false,
			Features: []string{"provision:aws-iam", "vault:cluster"}, UpdatedAt: fixed,
		}}
		var out ConfigurationResponse
		roundTrip(t, &in, &out)
		if out.Configuration.Environment != "live" || len(out.Configuration.Features) != 2 {
			t.Fatalf("configuration round trip lost data: %+v", out.Configuration)
		}
	})

	t.Run("DiscoveryIndex", func(t *testing.T) {
		in := DiscoveryIndex{
			APIVersion: Version, Service: "mutandae-control-plane", MediaType: MediaType,
			Resources: []DiscoveryResource{
				{Rel: "provision", Method: "POST", HREF: "/api/v1/demo/identities", Envelope: "provision"},
				{Rel: "use", Method: "POST", HREF: "/api/v1/identities/{id}/use", Envelope: "use"},
			},
		}
		var out DiscoveryIndex
		roundTrip(t, &in, &out)
		if len(out.Resources) != 2 || out.Resources[0].Rel != "provision" {
			t.Fatalf("discovery index lost resources: %+v", out.Resources)
		}
	})

	t.Run("ErrorResponse", func(t *testing.T) {
		in := Failure(NewError(ErrCodeNotFound, "identity not found"))
		var out ErrorResponse
		roundTrip(t, &in, &out)
		if out.Error.Code != ErrCodeNotFound || out.APIVersion != Version {
			t.Fatalf("error envelope round trip lost data: %+v", out)
		}
	})

	t.Run("AzureInteractiveEnvelopes", func(t *testing.T) {
		in := AzureSecretResponse{
			APIVersion: Version,
			Secret: AzureSecretResult{
				Credential: AzureCredential{KeyID: "key-1", Hint: "ABCD"}, SecretText: secret, OneTime: true,
			},
			Receipt: OperationReceipt{ID: "receipt-1", EventPublished: true},
		}
		var out AzureSecretResponse
		roundTrip(t, &in, &out)
		if out.Secret.SecretText != secret || !out.Secret.OneTime {
			t.Fatalf("azure secret round trip lost data: %+v", out.Secret)
		}
	})
}

func TestSnakeCaseWireNames(t *testing.T) {
	t.Parallel()
	fixture := wireFixture()
	identityJSON, err := json.Marshal(fixture)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"provider_id"`, `"renewal_period"`, `"expires_at"`, `"last_rotated_at"`} {
		if !strings.Contains(string(identityJSON), want) {
			t.Errorf("identity JSON missing %s", want)
		}
	}
	provisionJSON, err := json.Marshal(ProvisionResponse{APIVersion: Version, OneTimeSecret: "s", KeyID: "k"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"api_version"`, `"one_time_secret"`, `"key_id"`} {
		if !strings.Contains(string(provisionJSON), want) {
			t.Errorf("provision response JSON missing %s", want)
		}
	}
}

func TestEnumValidityFunctions(t *testing.T) {
	t.Parallel()
	for _, state := range KnownStates() {
		if !ValidState(string(state)) {
			t.Errorf("ValidState(%q) = false for a canonical state", state)
		}
	}
	for _, invalid := range []string{"", "ACTIVE", "deleted", "unknown"} {
		if ValidState(invalid) {
			t.Errorf("ValidState(%q) = true for a non-canonical state", invalid)
		}
	}
	if !ValidHealth(string(HealthHealthy)) || !ValidHealth(string(HealthAttention)) || ValidHealth("") || ValidHealth("critical") {
		t.Error("ValidHealth disagrees with the canonical health set")
	}
	for _, urgency := range []Urgency{UrgencyHealthy, UrgencyExpiring, UrgencyOverdue, UrgencyRetired} {
		if !ValidUrgency(string(urgency)) {
			t.Errorf("ValidUrgency(%q) = false for a canonical urgency", urgency)
		}
	}
	for _, status := range []RotationStatus{RotationPending, RotationRunning, RotationSucceeded, RotationFailed, RotationRollBack} {
		if !ValidRotationStatus(string(status)) {
			t.Errorf("ValidRotationStatus(%q) = false for a canonical status", status)
		}
	}
	for _, outcome := range []Outcome{OutcomeSuccess, OutcomeInProgress, OutcomeAttention, OutcomeFailure, OutcomeCancelled} {
		if !ValidOutcome(string(outcome)) {
			t.Errorf("ValidOutcome(%q) = false for a canonical outcome", outcome)
		}
	}
}

func TestTransitionMatrixIsExactlyTheDocumentedMachine(t *testing.T) {
	t.Parallel()
	allowed := map[[2]State]bool{
		{StateRegistered, StateActive}: true,
		{StateActive, StateRenewing}:   true,
		{StateActive, StateRetired}:    true,
		{StateRenewing, StateActive}:   true,
		{StateRenewing, StateRetired}:  true,
	}
	for _, from := range KnownStates() {
		for _, to := range KnownStates() {
			want := allowed[[2]State{from, to}]
			if got := CanTransition(from, to); got != want {
				t.Errorf("CanTransition(%s, %s) = %v, want %v", from, to, got, want)
			}
		}
	}
	// Unknown states are never transitionable, in either direction.
	for _, state := range KnownStates() {
		if CanTransition(State("bogus"), state) || CanTransition(state, State("bogus")) {
			t.Errorf("unknown state %q must not participate in transitions", "bogus")
		}
	}
}

func TestValidationErrorsCollectEveryFailure(t *testing.T) {
	t.Parallel()
	identity := MachineIdentity{State: State("bogus"), Health: Health("bogus")}
	err := ValidateIdentity(&identity)
	if err == nil {
		t.Fatal("ValidateIdentity(missing everything) = nil")
	}
	if !strings.Contains(err.Error(), "id is required") || !strings.Contains(err.Error(), "name is required") {
		t.Errorf("validation error should list every failure, got: %v", err)
	}
	for _, missing := range []string{"provider.provider is required", "provider.provider_id is required", "ownership.team is required", "ownership.service is required", "ownership.purpose is required"} {
		if !strings.Contains(err.Error(), missing) {
			t.Errorf("validation error missing %q, got: %v", missing, err)
		}
	}
	if !isConformanceError(err) {
		t.Errorf("validation errors must unwrap to ErrConformance, got: %v", err)
	}
}

func TestValidateIdentityRejectsBadDurationsAndStates(t *testing.T) {
	t.Parallel()
	identity := wireFixture()
	identity.Policy.RenewalPeriod = "90 days"
	if err := ValidateIdentity(&identity); err == nil {
		t.Fatal("invalid renewal_period must fail validation")
	}
	identity = wireFixture()
	identity.State = State("archived")
	if err := ValidateIdentity(&identity); err == nil {
		t.Fatal("invented state must fail validation")
	}
}

func TestValidateNilDocumentsAreConformanceErrors(t *testing.T) {
	t.Parallel()
	for name, check := range map[string]func() error{
		"identity":    func() error { return ValidateIdentity(nil) },
		"event":       func() error { return ValidateEvent(nil) },
		"rotationRun": func() error { return ValidateRotationRun(nil) },
	} {
		if err := check(); err == nil {
			t.Errorf("Validate(nil) for %s = nil, want a conformance error", name)
		}
	}
}

func TestValidateEventRejectsInvalidOutcome(t *testing.T) {
	t.Parallel()
	event := LifecycleEvent{ID: "evt-1", IdentityID: "i-1", Type: EventIdentityRegistered, Summary: "s", Actor: ActorControlPlane, Outcome: Outcome("fine"), At: time.Now()}
	if err := ValidateEvent(&event); err == nil {
		t.Fatal("event with an unknown outcome must fail validation")
	}
	event.Outcome = OutcomeSuccess
	if err := ValidateEvent(&event); err != nil {
		t.Fatalf("valid event failed validation: %v", err)
	}
}

func TestDurationParserRejectsGarbage(t *testing.T) {
	t.Parallel()
	for _, invalid := range []string{"", "P", "PT", "90 days", "P1M2D", "PH", "P1H", "1D", "P1X", "P..D", "P1DT"} {
		if _, err := ParseISO8601Duration(invalid); err == nil {
			t.Errorf("ParseISO8601Duration(%q) = nil error, want failure", invalid)
		}
	}
	for _, valid := range []struct {
		text string
		want time.Duration
	}{
		{"P1D", 24 * time.Hour},
		{"P2W", 14 * 24 * time.Hour},
		{"PT6H", 6 * time.Hour},
		{"PT30M", 30 * time.Minute},
		{"PT1.5S", 1500 * time.Millisecond},
		{"P1DT6H", 30 * time.Hour},
		{"  P90D  ", 90 * 24 * time.Hour},
	} {
		got, err := ParseISO8601Duration(valid.text)
		if err != nil {
			t.Errorf("ParseISO8601Duration(%q) error = %v", valid.text, err)
			continue
		}
		if got != valid.want {
			t.Errorf("ParseISO8601Duration(%q) = %v, want %v", valid.text, got, valid.want)
		}
	}
}

func TestDurationFormatRoundTrips(t *testing.T) {
	t.Parallel()
	for _, d := range []time.Duration{
		time.Second, 90 * time.Millisecond, 59 * time.Minute, time.Hour,
		6*time.Hour + 30*time.Minute + 15*time.Second + 250*time.Millisecond,
		24 * time.Hour, 90 * 24 * time.Hour, 0, -time.Hour,
	} {
		formatted := FormatISO8601Duration(d)
		parsed, err := ParseISO8601Duration(formatted)
		if err != nil {
			t.Errorf("FormatISO8601Duration(%v) = %q does not parse: %v", d, formatted, err)
			continue
		}
		want := d
		if want <= 0 {
			want = 0
		}
		if parsed != want {
			t.Errorf("round trip %v -> %q -> %v, want %v", d, formatted, parsed, want)
		}
	}
}

func isConformanceError(err error) bool {
	for current := err; current != nil; current = current.(interface{ Unwrap() error }).Unwrap() {
		if current == ErrConformance {
			return true
		}
	}
	return false
}

// TestVersionConstantsAreV1 pins the wire identity of this protocol version:
// a drift here is a breaking change and must be deliberate.
func TestVersionConstantsAreV1(t *testing.T) {
	if Version != "v1" {
		t.Errorf("Version = %q, want v1", Version)
	}
	if MediaType != "application/vnd.mutandae.v1+json" {
		t.Errorf("MediaType = %q", MediaType)
	}
	if ContentType != MediaType+"; charset=utf-8" {
		t.Errorf("ContentType = %q", ContentType)
	}
}
