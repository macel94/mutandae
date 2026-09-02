package protocol

// EventType values form the versioned lifecycle/audit taxonomy. They use a
// dotted namespace: <domain>.<verb>. Consumers SHOULD preserve the exact type
// string on events and correlate across identity, rotation-run, and actor.
type EventType string

// Discovery, registration, and ownership events.
const (
	EventIdentityDiscovered EventType = "identity.discovered"
	EventIdentityRegistered EventType = "identity.registered"
	EventIdentityImported   EventType = "identity.imported"
	EventOwnershipAssigned  EventType = "ownership.assigned"
	EventOwnershipChanged   EventType = "ownership.changed"
)

// Policy and renewal-health events.
const (
	EventPolicyApplied  EventType = "policy.applied"
	EventRenewalAlerted EventType = "renewal.alerted"
	EventExpiryImminent EventType = "expiry.imminent"
	EventExpiryOverdue  EventType = "expiry.overdue"
)

// Rotation workflow events. A rotation SHOULD emit exactly one started event
// followed by exactly one terminal event (completed or failed).
const (
	EventRotationRequested EventType = "rotation.requested"
	EventRotationStarted   EventType = "rotation.started"
	EventRotationCompleted EventType = "rotation.completed"
	EventRotationFailed    EventType = "rotation.failed"
	EventRotationRollBack  EventType = "rotation.rolled_back"
)

// Credential vault events. They record that a credential was delivered to,
// retrieved from, or revoked in the selected provider-native vault (Azure Key
// Vault, AWS Secrets Manager, GCP Secret Manager). Details carry vault names,
// versions, and key ids only — never secret material.
const (
	EventCredentialDelivered EventType = "credential.delivered"
	EventCredentialUsed      EventType = "credential.used"
	EventCredentialRevoked   EventType = "credential.revoked"
)

// Interactive provider integration events. These events may be published to
// Redis, but their details must remain redacted and secret-free.
const (
	EventIntegrationConnected EventType = "integration.connected"
	EventApplicationCreated   EventType = "application.created"
	EventSecretCreated        EventType = "secret.created"
	EventSecretRead           EventType = "secret.read"
	EventSecretInvalidated    EventType = "secret.invalidated"
	EventIntegrationClosed    EventType = "integration.closed"
)

// Decommissioning events.
const (
	EventIdentityRetired     EventType = "identity.retired"
	EventIdentityRevoked     EventType = "identity.revoked"
	EventIdentityResurrected EventType = "identity.resurrected"
)

// Actor names for the events the control plane records itself. Adapters may
// supply provider-scoped actor identifiers.
const (
	ActorOperator        = "operator"
	ActorControlPlane    = "control-plane"
	ActorProviderAdapter = "provider-adapter"
	ActorDiscovery       = "discovery"
)
