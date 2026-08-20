// Package config exposes the deliberately small, non-secret runtime description
// used by the public demo configuration page.
package config

import (
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// Public is immutable after construction and contains no raw environment
// values, connection strings, credentials, provider endpoints, or tenant IDs.
type Public struct {
	Environment string
	Persistence string
	Provider    string
	Clock       func() time.Time
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
		provider = "azure-entra (simulated)"
	}
	features := []string{
		"Azure/Entra simulator",
		"Protocol v1",
		"Synthetic data only",
		"Read-only configuration",
	}
	if persistence == "redis" {
		features = append(features, "Redis snapshot persistence", "Redis pub/sub change propagation")
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
