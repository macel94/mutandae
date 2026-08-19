package protocol

// State is the machine-identity lifecycle state. The value set is versioned and
// conformance-checked; a consumer MUST NOT invent new states for this version.
type State string

// The canonical machine-identity lifecycle states.
const (
	StateRegistered State = "registered"
	StateActive     State = "active"
	StateRenewing   State = "renewing"
	StateRetired    State = "retired"
)

// ValidState reports whether a value is a recognized state for this version.
func ValidState(value string) bool {
	switch State(value) {
	case StateRegistered, StateActive, StateRenewing, StateRetired:
		return true
	default:
		return false
	}
}

// Health is the renewal-health signal for a machine identity.
type Health string

const (
	HealthHealthy   Health = "healthy"
	HealthAttention Health = "attention"
)

// ValidHealth reports whether a value is a recognized health state.
func ValidHealth(value string) bool {
	switch Health(value) {
	case HealthHealthy, HealthAttention:
		return true
	default:
		return false
	}
}

// Urgency is a derived, time-boxed signal describing how soon action is needed.
// It is normally computed by a control plane from state plus expiry; consumers
// SHOULD treat it as advisory rather than authoritative.
type Urgency string

const (
	UrgencyHealthy  Urgency = "healthy"
	UrgencyExpiring Urgency = "expiring"
	UrgencyOverdue  Urgency = "overdue"
	UrgencyRetired  Urgency = "retired"
)

// ValidUrgency reports whether a value is a recognized urgency.
func ValidUrgency(value string) bool {
	switch Urgency(value) {
	case UrgencyHealthy, UrgencyExpiring, UrgencyOverdue, UrgencyRetired:
		return true
	default:
		return false
	}
}

// RotationStatus is the status of a RotationRun.
type RotationStatus string

const (
	RotationPending   RotationStatus = "pending"
	RotationRunning   RotationStatus = "running"
	RotationSucceeded RotationStatus = "succeeded"
	RotationFailed    RotationStatus = "failed"
	RotationRollBack  RotationStatus = "rolled_back"
)

// ValidRotationStatus reports whether a value is a recognized rotation status.
func ValidRotationStatus(value string) bool {
	switch RotationStatus(value) {
	case RotationPending, RotationRunning, RotationSucceeded, RotationFailed, RotationRollBack:
		return true
	default:
		return false
	}
}

// Outcome is a coarse result classification shared by events and rotations.
type Outcome string

const (
	OutcomeSuccess    Outcome = "success"
	OutcomeInProgress Outcome = "in_progress"
	OutcomeAttention  Outcome = "attention"
	OutcomeFailure    Outcome = "failure"
	OutcomeCancelled  Outcome = "cancelled"
)

// ValidOutcome reports whether a value is a recognized outcome.
func ValidOutcome(value string) bool {
	switch Outcome(value) {
	case OutcomeSuccess, OutcomeInProgress, OutcomeAttention, OutcomeFailure, OutcomeCancelled:
		return true
	default:
		return false
	}
}

// ErrorCode is a stable, machine-readable error classification carried on
// ErrorResponse and surfaced by adapters' errors.
type ErrorCode string

const (
	ErrCodeInvalidRequest     ErrorCode = "invalid_request"
	ErrCodeConformanceFailure ErrorCode = "conformance_failure"
	ErrCodeNotFound           ErrorCode = "not_found"
	ErrCodeInvalidTransition  ErrorCode = "invalid_transition"
	ErrCodeAlreadyRetired     ErrorCode = "already_retired"
	ErrCodeRotationInProgress ErrorCode = "rotation_in_progress"
	ErrCodeProviderFailure    ErrorCode = "provider_failure"
	ErrCodeUnsupportedVersion ErrorCode = "unsupported_version"
	ErrCodeConflict           ErrorCode = "conflict"
	ErrCodeInternal           ErrorCode = "internal"
	ErrCodeUnimplemented      ErrorCode = "unimplemented"
)

// Error carries protocol error details. ErrorCode is the stable classification;
// Message is human-readable only. Details may carry structured context.
type Error struct {
	Code    ErrorCode         `json:"code"`
	Message string            `json:"message"`
	Details map[string]string `json:"details,omitempty"`
}
