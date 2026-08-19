// Package protocol defines the μTandae Protocol: the versioned, provider-neutral
// wire contract used between cloud provider adapters, the Mutandae control
// plane (backend), and the frontend/API consumers.
//
// The protocol deliberately owns only the *semantics* of machine-identity
// lifecycle governance. It never encodes provider-specific renewal mechanics,
// credential material, service endpoints, or hostnames. Provider identity may
// appear as opaque ProviderBindings; the mechanics of executing a renewal
// belong to provider adapters behind the ProviderAdapter boundary.
//
// Everything in this package is meant to be a stable, versioned, testable
// contract:
//
//   - Enumerations (State, Health, Urgency, RotationStatus, Outcome, ErrorCode)
//   - Object schemas (MachineIdentity, ProviderBinding, Ownership,
//     LifecyclePolicy, CredentialReference, LifecycleEvent, RotationRun)
//   - Message envelopes for control-plane operations
//   - ISO-8601 duration helpers so renewal periods are wire-portable
//   - Conformance validation so any consumer (cloud adapter, backend, frontend)
//     can check that a document conforms to the version.
package protocol

// Version is the current protocol version as a semantic-style identifier.
// Consumers SHOULD negotiate with the "api" field in a discovery index and the
// "api_version" field on every envelope rather than hard-coding a string.
const Version = "v1"

// MediaType is the versioned JSON representation of the μTandae Protocol.
const MediaType = "application/vnd.mutandae.v1+json"

// ContentType is what servers emit for protocol responses and what conformance
// clients SHOULD accept. It is the versioned media type plus the UTF-8 charset.
const ContentType = MediaType + "; charset=utf-8"

// Accept informs conformance/versioning: servers SHOULD reject requests whose
// Accept header names an unsupported protocol version.
const Accept = MediaType
