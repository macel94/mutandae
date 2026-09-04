// Package config exposes the deliberately small, non-secret runtime description
// used by the public demo configuration page.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/mutandae/mutandae/pkg/protocol"
)

// ValidateAuthMode validates the deployment authentication mode and enforces
// the live-environment fail-closed rule. The web package owns the protocol
// implementation; keeping this policy here lets the composition root validate
// it before wiring providers or starting an HTTP server.
func ValidateAuthMode(environment, mode string) error {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "none"
	}
	switch mode {
	case "none", "oidc", "token":
	default:
		return fmt.Errorf("MUTANDAE_AUTH_MODE must be none, oidc, or token (got %q)", mode)
	}
	if strings.EqualFold(strings.TrimSpace(environment), "live") && mode == "none" {
		return fmt.Errorf("MUTANDAE_AUTH_MODE=none is not allowed in the live environment")
	}
	return nil
}

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
	Allow []string
	Deny  []string
}

// Public is immutable after construction and contains no raw environment
// values, connection strings, credentials, provider endpoints, or tenant IDs.
type Public struct {
	Environment string
	Persistence string
	Provider    string
	// AuthMode, AuthRoles, and TokensConfigured are safe operational metadata;
	// they never contain issuer secrets, token values, token digests, or keys.
	AuthMode         string
	AuthRoles        []string
	TokensConfigured bool
	Clock            func() time.Time
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
	providers := make([]protocol.ProviderDescriptor, 0, len(p.Providers))
	for _, descriptor := range p.Providers {
		providers = append(providers, protocol.ProviderDescriptor{
			Kind: descriptor.Kind, Label: descriptor.Label, Scope: descriptor.Scope,
			Allow: append([]string(nil), descriptor.Allow...), Deny: append([]string(nil), descriptor.Deny...),
		})
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
		Providers:       providers,
		UpdatedAt:       now,
	}
}
