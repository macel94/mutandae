// Package config exposes the deliberately small, non-secret runtime description
// used by the public demo configuration page.
package config

import (
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// ProviderDescriptor names one wired provider adapter and the public tenant
// scope it governs. Scope states the identifier explicitly — "tenant <id>"
// for Azure/Entra ID, "account <id>" for AWS IAM, "project <id>" for GCP IAM
// — so the UI can show which Azure tenant, AWS account, or GCP project the
// demo is attached to. Identifiers of this kind are not credentials: they are
// the opaque, non-secret names that tokens and ARNs already expose.
type ProviderDescriptor struct {
	Kind  string
	Label string
	Scope string
}

// Public is immutable after construction and contains no raw environment
// values, connection strings, credentials, provider endpoints, or tenant IDs.
type Public struct {
	Environment string
	Persistence string
	Provider    string
	Clock       func() time.Time
	// Providers describes the wired adapters with their explicit tenant
	// scopes; it may be empty, in which case the UI falls back to the
	// feature-flag-derived summary without identifiers.
	Providers []ProviderDescriptor
	// Features advertises safe, non-secret capability flags to the UI. The
	// composition root adds "provision:<kind>" for each real tenant that can
	// create zero-permission identities.
	Features []string
}

func (p Public) Configuration() protocol.Configuration {
	now := time.Now().UTC()
	if p.Clock != nil {
		now = p.Clock().UTC()
	}
	environment := p.Environment
	if environment == "" {
		environment = "preview"
	}
	persistence := p.Persistence
	if persistence == "" {
		persistence = "in-memory"
	}
	provider := p.Provider
	if provider == "" {
		provider = "multi-cloud (azure-entra, aws-iam, gcp-iam simulated)"
	}
	features := []string{
		"Multi-cloud simulator for the public lifecycle inventory",
		"Azure/Entra ID, AWS IAM, and GCP IAM adapters",
		"Protocol v1",
		"Optional ephemeral Azure Graph integration",
		"Graph mutations constrained by Application.ReadWrite.OwnedBy",
		"Customer credentials never persisted by Mutandae",
		"Read-only deployment configuration",
	}
	features = append(features, p.Features...)
	if persistence == "redis" {
		features = append(features, "Redis snapshot persistence", "Redis pub/sub change propagation", "Redacted integration event receipts")
	} else {
		features = append(features, "Process-local demo state")
	}
	return protocol.Configuration{
		Service:         "mutandae-control-plane",
		ProtocolVersion: protocol.Version,
		MediaType:       protocol.MediaType,
		Environment:     environment,
		Provider:        provider,
		Persistence:     persistence,
		ReadOnly:        true,
		Features:        features,
		UpdatedAt:       now,
	}
}
