# Provider adapters and the μTandae Protocol

This document is the companion reference to
[protocol.md](protocol.md). It describes the provider side of the μTandae
Protocol: what a `ProviderBinding` promises, the provider adapters that ship in
the public demo (the simulated Azure/Entra ID, AWS IAM, and GCP IAM adapters
plus the composite multi-cloud adapter that fans discovery out), the `Adapter`
boundary the control plane consumes, and how the real-world interactive
integration extension generalizes across clouds.

The protocol itself stays provider-neutral. Everything cloud-specific —
renewal mechanics, credential handling, provider API calls, endpoints, and
hostnames — lives behind an adapter boundary, never in the wire contract.

## The ProviderBinding opacity contract

`ProviderBinding` is the bridge between a governed identity and its provider
domain. Its contents are deliberately opaque to the control plane: the control
plane, frontend, and other protocol consumers depend on the provider-neutral
contract, never on cloud SDK details. The semantics of the generic
identifier fields (`tenant_id`, `object_id`, `region`, `account_id`,
`project_id`) are decided by each provider adapter.

The control plane correlates on the identity `id` it assigns, not on provider
internals. Adapters populate `ProviderBinding` from their provider-local view;
the gateway and UI render `provider` as a stable kind and leave the rest alone.
Because the binding is opaque, adding AWS IAM and GCP IAM as first-class
providers required no protocol schema change — only shared conventions for how
each provider populates the generic fields. Those conventions are spelled out
in [protocol.md § 2.2 ProviderBinding](protocol.md) and summarized for each
adapter below.

## The Adapter boundary

A provider adapter implements a small, consuming-side interface. The control
plane, via the `lifecycle` package, speaks protocol types end to end and never
depends on a concrete cloud SDK; a provider adapter is the only place that
translates protocol operations into provider mechanics.

```go
// Adapter is the provider-aware execution boundary the control plane consumes.
// Implementations translate protocol operations into provider mechanics and
// return protocol objects plus evidence.
type Adapter interface {
    // Kind returns a stable provider identifier, e.g. "azure-entra".
    Kind() string
    // Discover returns the provider's current view of machine identities.
    Discover(ctx context.Context) ([]protocol.MachineIdentity, error)
    // Rotate performs a rotation of the identity's credential and returns the
    // provider-observed identity with new credential evidence.
    Rotate(ctx context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error)
    // Retire decommissions the identity in the provider and returns the
    // provider-observed (retired) identity.
    Retire(ctx context.Context, identity protocol.MachineIdentity) (protocol.MachineIdentity, error)
}
```

- `Kind()` is a stable provider token such as `azure-entra`, `aws-iam`, or
  `gcp-iam`.
- `Discover` returns the provider's current view of governed identities. The
  control plane assigns governance `id` values; the provider fills the
  `ProviderBinding` and ownership/policy/credential facts it observes.
- `Rotate` refreshes an identity's credential and returns provider-observed
  evidence (a new key ID, fingerprint, and scheduled expiry).
- `Retire` decommissions the identity in the provider and returns the observed
  retired identity.

Sentinel errors from the lifecycle store map onto protocol `ErrorCode`s
(`not_found`, `invalid_transition`, `already_retired`, `rotation_in_progress`,
`provider_failure`, `conflict`, `conformance_failure`) for conformant failure
envelopes.

## Simulated adapters shipped in the public demo

The public demo is intentionally dependency-light: the Go standard library,
`html/template`, HTMX, Alpine.js, and an in-memory simulator. The simulator is
honest — it models meaningful lifecycle and audit outcomes without containing
production provider credentials or pretending to be a production Azure/AWS/GCP
adapter. All simulated adapters live under `internal/provider/` and are
composed behind one control-plane boundary by `multicloud.go`.

| Provider kind | Adapter file | Simulated domain | Seeded identities |
| --- | --- | --- | --- |
| `azure-entra` | `internal/provider/azuresimulator.go` | A tenant with application registrations | `payments-api`, `data-pipeline`, `inventory-sync`, `legacy-reporting` |
| `aws-iam` | `internal/provider/awssimulator.go` | An AWS account with IAM users | `orders-deployer`, `data-exporting`, `metrics-publisher` |
| `gcp-iam` | `internal/provider/gcpsimulator.go` | A GCP project with service accounts | `inventory-broker`, `ml-training-runtime`, `catalog-replication` |
| `multi-cloud` (composite) | `internal/provider/multicloud.go` | Aggregates the per-cloud sub-adapters | None — fans the sub-adapters' views out |

The `aws-iam` and `gcp-iam` adapters (`awssimulator.go`, `gcpsimulator.go`)
implement the adapter contract described here and populate the
`ProviderBinding` fields defined in [protocol.md § 2.2](protocol.md) and
summarized in each section below. The seeded friendly names are the adapter's
`name`/`display_name`, exactly as the simulator exposes them; the full seeded
inventory is that module's concern and not part of the protocol.

### `azure-entra` (`azuresimulator.go`)

- **Kind:** `azure-entra`.
- **Populated `ProviderBinding`:** `provider`, `provider_id` (the application
  object ID), `tenant_id`, `object_id` (equals `provider_id`), `region`
  (`westeurope`). `account_id`/`project_id` are unused.
- **CredentialReference:** `kind=client_secret`,
  `delivery=keyvault-ref`, `location=keyvault://mutandae-vault/secrets/<name>`,
  plus a fingerprint and key id.
- **`Discover`:** returns its non-disabled application registrations as
  identities at `register`/`active` state. Disabled/retired registrations are
  not rediscovered.
- **`Rotate`:** issues a new key id and fingerprint, resets the scheduled
  expiry from the policy, marks health `healthy`, and returns the
  provider-observed identity with the new credential evidence.
- **`Retire`:** marks the registration disabled; the identity returns as
  `retired`.

### `aws-iam` / `awssimulator.go`

- **Kind:** `aws-iam`.
- **Seeded identities:** `orders-deployer`, `data-exporting`,
  `metrics-publisher`.
- **Populated `ProviderBinding`:** `provider="aws-iam"`,
  `provider_id` = IAM user name (or role ARN), `account_id` = 12-digit AWS
  account ID, `region` = AWS region (e.g. `us-east-1`); `tenant_id` and
  `object_id` unused; `project_id` optional/unused.
- **CredentialReference:** `kind=access_key`,
  `delivery=secret-manager` (or `environment`),
  `location=iam://<accountID>/user/<userName>`.
- **`Discover`:** lists enabled IAM users in the modeled account and returns
  their access-key view. Disabled/retired users are not rediscovered.
- **`Rotate`:** creates a new access key in the model, rotates the reference
  and expiry, and returns evidence.
- **`Retire`:** disables the modeled user's keys; the identity returns as
  `retired`.

### `gcp-iam` / `gcpsimulator.go`

- **Kind:** `gcp-iam`.
- **Seeded:** `inventory-broker`, `ml-training-runtime`,
  `catalog-replication`.
- **Populated `ProviderBinding`:** `provider="gcp-iam"`,
  `provider_id` = service-account unique ID or the email
  `<name>@<projectID>.iam.gserviceaccount.com`, `project_id` = GCP project ID,
  `region` = GCP region (e.g. `us-central1`); `account_id`, `tenant_id`, and
  `object_id` unused.
- **CredentialReference:** `kind=service_account_key`,
  `delivery=secret-manager`,
  `location=iam://projects/<projectID>/serviceAccounts/<email>/keys/<keyID>`.
- **`Discover`:** lists modeled service accounts in the project.
- **`Rotate`:** generates a new service-account key in the model and updates
  the credential evidence and expiry.
- **`Retire`:** deactivates/removes the modeled service account key; the
  identity returns as `retired`.

### `multi-cloud` composite (`multicloud.go`)

`MultiProvider` aggregates several `CloudAdapter`s behind the same lifecycle
boundary so a single control plane can govern Azure/Entra ID, AWS IAM, and GCP
IAM. It never needs to know provider mechanics:

- **`Kinds()`:** the sorted provider kinds it governs.
- **`Kind()`:** `"multi-cloud"` (the composite is not a real cloud provider and
  is never placed in a `ProviderBinding`; identity bindings keep their
  originating kind).
- **`Discover`:** fans discovery out across every sub-adapter and dedupes by
  `(provider, provider_id)`.
- **`Rotate`/`Retire`:** routes each operation to the sub-adapter whose `Kind`
  matches the identity's `ProviderBinding.provider`; reports an error when no
  sub-adapter governs that kind.

Construction rejects nil adapters, empty kinds, duplicate kinds, and an empty
provider set, so the control plane never discovers from an empty or ambiguous
inventory.

## Real-world integration extension

The public demo is synthetic. The interactive Azure / Entra integration
documented in [azure-integration.md](azure-integration.md) shows how µTandae
generalizes to a real provider without compromising the protocol boundary.

The pattern is: **a caller provides cloud-specific credentials to an opt-in,
expiring, in-memory session.** The credentials are never persisted by
Mutandae; secrets are write-only; and the session enforces least-privilege
permissions per cloud.

The Azure flow is the reference implementation:

- connect with `tenant_id`, `client_id`, and a temporary `client_secret` to an
  in-memory session (opaque HttpOnly cookie, separate CSRF token, throttling,
  maximum ten-minute lifetime);
- list safe application metadata; create owned applications; add one-time
  secrets (optionally stored in an existing Key Vault); and
- invalidate the Graph password credential through `removePassword`, disabling
  the matching vault version when one is configured.

The same contract generalizes to AWS IAM and GCP IAM by swapping the
credential shape and the least-privilege permission set:

| Cloud | Connect credentials (write-only) | Least-privilege permissions |
| --- | --- | --- |
| Azure / Entra ID | `tenant_id`, `client_id`, `client_secret` | Microsoft Graph `Application.ReadWrite.OwnedBy` (mutations only on owned applications) |
| AWS IAM | AWS access key ID + secret access key | `iam:ListUsers`, `iam:ListAccessKeys`, `iam:CreateAccessKey`, `iam:UpdateAccessKey`, `iam:DeleteAccessKey` |
| GCP IAM | GCP service-account JSON key | `roles/iam.serviceAccountKeyAdmin` |

Across clouds the invariants are identical:

- Mutandae never persists client credentials; each session is in-memory,
  expiring, and bound to a process-local session cookie.
- Generated secrets are **write-only**: they may be returned once at creation
  (or stored in a configured vendor secret manager), never read back later,
  never logged, and never written into a snapshot, event, pub/sub payload, or
  normal response.
- Least-privilege permissions are enumerated per cloud *before* any
  credentials are submitted, mirroring the Azure
  `GET /api/v1/integration/requirements` contract.

### Honest trust boundaries

The trust-boundary notes that apply to the Azure interactive integration apply
equally to AWS and GCP:

- A client-credential / API-key / service-account session authenticates an
  application or service principal, not a human. Any "owner" or "subject"
  metadata supplied by the browser cannot truthfully prove which humans may
  read a secret; the vendor's own authorization model (Azure RBAC or delegated
  Entra auth; AWS IAM policies & KMS; GCP IAM on Secret Manager) is the real
  boundary, configured outside this demo.
- Seating a secret in a configured vendor secret manager is additive and
  optional; Mutandae does not create secret-manager instances, roles, or
  policies and reports a plain reason (not a distributed transaction) if the
  store write fails after a provider mutation succeeds.
- Provider mutations and any local Redis publication are separate systems: an
  `event_published: false` response must never claim an atomic provider-plus-
  Redis commit.
- These interactive flows are opt-in, do not replace the synthetic inventory,
  and never place customer credentials into the public lifecycle snapshot.
- Adapters surface provider-scoped actor identifiers; control-plane actor
  names (`operator`, `control-plane`, `provider-adapter`, `discovery`) remain
  the stable correlation basis.

## References

- `docs/protocol.md` — the provider-neutral wire contract and the per-provider
  `ProviderBinding` field conventions.
- `docs/azure-integration.md` — the reference interactive extension and its
  trust-boundary notes.
- `pkg/protocol/models.go` — the `ProviderBinding` Go type and source comments.
- `internal/provider/` — the simulated adapters and the multi-cloud composite.
- `internal/lifecycle/adapter.go` — the `Adapter` interface the control plane
  consumes.