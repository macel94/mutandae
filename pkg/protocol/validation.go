package protocol

import (
	"fmt"
	"strings"
)

// Conformance errors returned by the Validate* helpers. Wrap with fmt so errors
// carry field context.
var (
	// ErrConformance is the sentinel all validation errors unwrap to,
	// regardless of which field failed.
	ErrConformance = fmt.Errorf("protocol: document does not conform to %s", Version)
)

// ValidationErrors is returned when a document has multiple conformance
// failures, so consumers can surface them all at once.
type ValidationErrors []string

func (v ValidationErrors) Error() string {
	return ErrConformance.Error() + ": " + strings.Join(v, "; ")
}

func (v ValidationErrors) Unwrap() error { return ErrConformance }

// ValidateIdentity enforces the versioned conformance rules for a
// MachineIdentity.
func ValidateIdentity(v *MachineIdentity) error {
	if v == nil {
		return fmt.Errorf("%w: identity is nil", ErrConformance)
	}
	var errs ValidationErrors
	require := func(ok bool, msg string) {
		if !ok {
			errs = append(errs, msg)
		}
	}

	require(v.ID != "", "id is required")
	require(v.Name != "", "name is required")
	require(v.Provider.Provider != "", "provider.provider is required")
	require(v.Provider.ProviderID != "", "provider.provider_id is required")
	require(v.Ownership.Team != "", "ownership.team is required")
	require(v.Ownership.Service != "", "ownership.service is required")
	require(v.Ownership.Purpose != "", "ownership.purpose is required")
	require(ValidState(string(v.State)), fmt.Sprintf("state %q is invalid", v.State))
	require(ValidHealth(string(v.Health)), fmt.Sprintf("health %q is invalid", v.Health))
	if v.Policy.RenewalPeriod != "" {
		if _, err := ParseISO8601Duration(v.Policy.RenewalPeriod); err != nil {
			errs = append(errs, "policy.renewal_period is not a valid ISO-8601 duration")
		}
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// ValidateEvent enforces conformance rules for a LifecycleEvent.
func ValidateEvent(v *LifecycleEvent) error {
	if v == nil {
		return fmt.Errorf("%w: event is nil", ErrConformance)
	}
	var errs ValidationErrors
	if v.ID == "" {
		errs = append(errs, "id is required")
	}
	if v.IdentityID == "" {
		errs = append(errs, "identity_id is required")
	}
	if v.Type == "" {
		errs = append(errs, "type is required")
	}
	if v.Summary == "" {
		errs = append(errs, "summary is required")
	}
	if v.Actor == "" {
		errs = append(errs, "actor is required")
	}
	if v.Outcome == "" || !ValidOutcome(string(v.Outcome)) {
		errs = append(errs, "outcome is invalid")
	}
	if v.At.UTC().IsZero() {
		errs = append(errs, "at is required")
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// ValidateRotationRun enforces conformance rules for a RotationRun.
// ValidatePlannedOperation enforces the stable provider-neutral operation
// shape. It intentionally does not enumerate provider operation tokens so new
// adapters can add truthful short verbs without changing protocol semantics.
func ValidatePlannedOperation(v *PlannedOperation) error {
	if v == nil {
		return fmt.Errorf("%w: planned operation is nil", ErrConformance)
	}
	var errs ValidationErrors
	if strings.TrimSpace(v.Op) == "" {
		errs = append(errs, "op is required")
	}
	if strings.TrimSpace(v.Identity) == "" {
		errs = append(errs, "identity is required")
	}
	if strings.TrimSpace(v.Detail) == "" {
		errs = append(errs, "detail is required")
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// ValidatePlan checks the stable dry-run envelope and every operation.
func ValidatePlan(v *Plan) error {
	if v == nil {
		return fmt.Errorf("%w: plan is nil", ErrConformance)
	}
	var errs ValidationErrors
	if !v.DryRun {
		errs = append(errs, "dry_run must be true")
	}
	if strings.TrimSpace(v.ExpiresHint) == "" {
		errs = append(errs, "expires_hint is required")
	}
	if v.Operations == nil {
		errs = append(errs, "operations is required")
	}
	for i := range v.Operations {
		if err := ValidatePlannedOperation(&v.Operations[i]); err != nil {
			errs = append(errs, fmt.Sprintf("operations[%d]: %v", i, err))
		}
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// ValidateRotateRequest validates the provider-neutral rotate request. Go's
// JSON decoder performs the type check for DryRun; a JSON string such as
// {"dry_run":"true"} is rejected before this value is constructed.
func ValidateRotateRequest(v *RotateRequest) error {
	if v == nil {
		return fmt.Errorf("%w: rotate request is nil", ErrConformance)
	}
	if strings.TrimSpace(v.ID) == "" {
		return fmt.Errorf("%w: id is required", ErrConformance)
	}
	return nil
}

// ValidateRetireRequest validates the provider-neutral retire request.
func ValidateRetireRequest(v *RetireRequest) error {
	if v == nil {
		return fmt.Errorf("%w: retire request is nil", ErrConformance)
	}
	if strings.TrimSpace(v.ID) == "" {
		return fmt.Errorf("%w: id is required", ErrConformance)
	}
	return nil
}

func ValidateRotationRun(v *RotationRun) error {
	if v == nil {
		return fmt.Errorf("%w: rotation run is nil", ErrConformance)
	}
	var errs ValidationErrors
	if v.ID == "" {
		errs = append(errs, "id is required")
	}
	if v.IdentityID == "" {
		errs = append(errs, "identity_id is required")
	}
	if v.Status == "" || !ValidRotationStatus(string(v.Status)) {
		errs = append(errs, "status is invalid")
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}
