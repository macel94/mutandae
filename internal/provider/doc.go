// Package provider contains the simulated cloud adapter used by the public
// demo. It demonstrates the provider-aware execution boundary: the control
// plane speaks the μTandae Protocol, and a provider adapter translates those
// protocol operations into provider mechanics.
//
// This package ships one adapter, azure-entra, that fakes a Microsoft Entra ID
// tenant's application registrations well enough to model meaningful lifecycle
// and audit outcomes: discovery, rotation with provider evidence (new key id,
// credential fingerprint, verified expiry), and retirement. It deliberately
// contains no production Azure SDKs, credentials, or endpoints.
//
// The Simulator implements the Adapter interface defined by the consuming
// control-plane package. It only depends on the public protocol, keeping the
// provider implementation provider-neutral at the domain layer.
package provider
