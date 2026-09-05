# Changelog

All notable changes to Mutandae are documented here. The project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and semantic versioning
where releases are cut.

## [Unreleased] - 2026-09-04

### Added

- Real AWS IAM, GCP IAM, and Azure / Entra adapters behind the provider-neutral
  lifecycle boundary, with honest one-time credential handling and native-vault
  delivery paths.
- Provider scope allow-lists and demo/evaluation prefixes that keep discovery
  broad enough for inventory while limiting mutations to disposable identities.
- Dry-run and lifecycle guardrails for safe previews, including explicit retire
  confirmation, bounded demo provisioning, and correlated audit outcomes.
- Authentication and authorization foundations: auth modes, RBAC/API-token
  scopes, CSRF/session protections, and provider-specific integration
  requirements for the interactive Azure path.
- Operational visibility through metrics, structured logs, correlation IDs, and
  a JSONL audit-file sink in addition to Redis-backed event delivery.
- A lifecycle sweeper and fixes for retired identities so terminal identities
  no longer appear as active needs-attention work.
- Docker Compose five-minute quickstart with Redis, a disposable in-memory
  Vault dev server, a namespaced KV mount, simulated three-cloud inventory, and
  a persistent local audit volume.
- Least-privilege Azure, AWS, and GCP governor provisioning scripts, with
  cleanup instructions and no committed credentials.
- Nightly/manual real-cloud CI with GitHub OIDC setup for AWS, Azure, and GCP,
  plus explicit compatibility documentation for the adapters that still need
  static credential material.

### Changed

- The dashboard and protocol now present the multi-cloud inventory, ownership
  scopes, rotation/retirement evidence, vault retrieval, mobile layout, and
  provider-specific lifecycle state as one coherent control-plane experience.
- Vault delivery now supports the cluster-local HashiCorp KV v2 mirror and
  optional AWS Secrets Manager, GCP Secret Manager, and Azure Key Vault copies;
  stored events contain references and metadata, never secret values.
- CI keeps the existing test/build/publish and immutable-image attestation path
  while separating formatting, race, vet, and Compose configuration checks.
- Production delivery documentation now covers the open-core boundary,
  licensing, security expectations, and contribution workflow alongside the
  GitOps deployment contract.

### Fixed

- The live-environment authentication policy no longer refuses to start when
  `MUTANDAE_AUTH_MODE=none`: the hosted public demo runs open by design
  (rate-limited, scoped to the `mutandae-demo-*` namespace), so an
  unauthenticated live deployment now emits a loud startup warning instead of
  failing the rollout. Invalid auth modes remain hard errors.
- Retired identities no longer inflate active attention counts or show stale
  expiry state, and permanent deletion remains distinct from the audit trail.
- AWS retirement tolerates an already-removed IAM user, while GCP key creation
  and Azure directory operations absorb documented provider propagation lag.
- GCP vault paths derived from service-account email names are sanitized and
  provider descriptors retain the correct tenant/project/account scopes.
- Container and hosted deployment health checks consistently use `/readyz` for
  readiness and `/livez` for liveness, including the new OCI image
  `HEALTHCHECK`.

### Security

- Container execution remains unprivileged, drops capabilities, uses a read-only
  root filesystem where applicable, and now has a bounded `/readyz`
  `HEALTHCHECK`; Compose's Vault root token is explicitly dev-only and never a
  production secret.
- Cloud governor recipes grant only the documented key/credential lifecycle
  actions and namespace-scoped secret access. Real-cloud CI prefers short-lived
  OIDC credentials and calls out current Azure/GCP static-credential limits
  rather than masking them.
- Secret values are kept out of snapshots, events, logs, HTML, CI output, and
  committed configuration; one-time provider outputs are clearly marked for
  immediate secure capture and revocation.
- Security, license, and contribution guidance now accompanies the runnable
  demo so operators can distinguish a local preview from a production control
  plane.
