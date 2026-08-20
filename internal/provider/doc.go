// Package provider contains the simulated cloud adapter used by the public
// demo. It demonstrates the provider-aware execution boundary: the control
// plane speaks the μTandae Protocol, and a provider adapter translates those
// protocol operations into provider mechanics.
//
// This package ships the public azure-entra simulator plus an optional
// standard-library real Azure client for the interactive Configuration panel.
// The real client uses Microsoft Graph client credentials and an existing Key
// Vault through short-lived process-local sessions; it never persists
// credentials or tokens and enforces Graph's Application.ReadWrite.OwnedBy
// ownership boundary before mutations. The simulator fakes a Microsoft Entra
// tenant's registrations well enough to model discovery, rotation with
// provider evidence, and retirement.
//
// The Simulator implements the Adapter interface defined by the consuming
// control-plane package. It only depends on the public protocol, keeping the
// provider implementation provider-neutral at the domain layer.
package provider
