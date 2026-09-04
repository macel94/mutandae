# Provider adapters and the μTandae Protocol

This document is the companion reference to
[protocol.md](protocol.md). It describes the provider side of the μTandae
Protocol: what a `ProviderBinding` promises, the simulated and real provider
adapters that ship in the public release (Azure/Entra ID, AWS IAM, and GCP IAM
plus the composite multi-cloud adapter that fans discovery out), the `Adapter`
boundary the control plane consumes, and how provider-specific integrations
remain behind that boundary.

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

## Adapters shipped in the public release

The project remains dependency-light: the Go standard library,
`html/template`, HTMX, Alpine.js, and provider clients implemented with
`net/http` and standard cryptography/encoding packages. Credential-less
simulators remain the local-development and unit-test default. Real adapters
are also in-tree and are wired by `cmd/mutandae` when their credential
environment is present.

The simulator is honest — it models meaningful lifecycle and audit outcomes
without containing production provider credentials or pretending that a cloud
mutation occurred. All adapters are composed behind one control-plane boundary
by `multicloud.go`.

| Provider kind | Real adapter | Simulator | Identity class in scope |
| --- | --- | --- | --- |
| `azure-entra` | `internal/provider/azurecloud.go` + `azure.go` | `internal/provider/azuresimulator.go` | Entra application password credentials |
| `aws-iam` | `internal/provider/aws.go` | `internal/provider/awssimulator.go` | AWS IAM user access keys |
| `gcp-iam` | `internal/provider/gcp.go` | `internal/provider/gcpsimulator.go` | GCP service-account user-managed keys |
| `multi-cloud` (composite) | `internal/provider/multicloud.go` | Same composite | Fans the per-provider views out; no independent identity class |

The real clients use Microsoft Graph/Key Vault HTTP calls, AWS IAM Query API
SigV4 signing, and GCP IAM JWT assertion/REST calls. No cloud SDK is required.
Both real and simulated adapters implement the same provider contract and
populate the `ProviderBinding` fields defined in [protocol.md § 2.2](protocol.md).
The seeded friendly names belong to the simulator and are not part of the
protocol.

### `azure-entra` (`azuresimulator.go` and `azurecloud.go`)

#### Identity classes covered

- **Covered today:** Entra application password credentials. The real Graph
  adapter and simulator expose the same lifecycle shape; the demo real adapter
  restricts mutations to the `mutandae-demo-*` namespace.
- **Not covered yet:** Entra managed identities, certificate credentials, and
  federated credentials. See [roadmap.md](roadmap.md) for targets.

- **Kind:** `azure-entra`.
- **Populated `ProviderBinding`:** `provider`, `provider_id` (the application
  object ID), `tenant_id`, `object_id` (equals `provider_id`), `region`
  (`westeurope`). `account_id`/`project_id` are unused.
- **CredentialReference:** `kind=client_secret`,
  `delivery=secret-manager`, `location=graph://applications/<object-id>`, plus
  a fingerprint and key id. A configured Azure Key Vault may hold the plaintext
  value, but the control-plane reference remains redacted.
- **`Discover`:** returns demo-namespaced application registrations that still
  have a credential. Applications with no live credential are not rediscovered.
- **`Rotate`:** issues a new key id and fingerprint, removes the prior password
  credential, resets the scheduled expiry from the policy, and returns the
  provider-observed identity with the new credential evidence.
- **`Retire`:** deletes the demo application registration from Graph; the
  control plane retains a retired record and the provider object is no longer
  rediscovered.

### `aws-iam` / `aws.go` and `awssimulator.go`

#### Identity classes covered

- **Covered today:** AWS IAM user access keys, including real SigV4 discovery,
  rotation, and retirement.
- **Not covered yet:** IAM roles, instance profiles, and IAM Identity Center /
  SSO. See [roadmap.md](roadmap.md) for targets.

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
- **`Retire`:** deletes the modeled user's access keys and best-effort removes
  its login profile; the identity returns as `retired` and is no longer
  rediscovered with no active keys.

### `gcp-iam` / `gcp.go` and `gcpsimulator.go`

#### Identity classes covered

- **Covered today:** GCP service-account user-managed keys, including real JWT
  assertion/REST discovery, rotation, and retirement.
- **Not covered yet:** SPIFFE/SPIRE, general X.509 workload identities, and
  other non-key federation credentials. See [roadmap.md](roadmap.md) for
  targets.

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
- **`Retire`:** deletes every user-managed service-account key. The service
  account itself remains for provider-side cleanup; with no user-managed keys,
  it is no longer rediscovered and the identity returns as `retired`.

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

The local default is synthetic, but real Azure/Entra, AWS IAM, and GCP IAM
adapters also ship in-tree for opt-in evaluation and namespace-scoped demo
operation. The interactive Azure / Entra integration documented in
[azure-integration.md](azure-integration.md) is the reference for a caller-
provided session and shows how µTandae generalizes to a real provider without
compromising the protocol boundary.

The pattern is: **a caller provides cloud-specific credentials to an opt-in,
expiring, in-memory session or composition-root adapter.** Credentials are
never persisted in lifecycle snapshots; secrets are write-only at provider
creation; and cloud IAM plus adapter scope checks enforce least privilege.

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

The trust-boundary notes that apply to the Azure interactive integration and
real adapter apply equally to AWS and GCP:

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

## Writing a third-party adapter

Third-party adapters should implement the smallest boundary needed by the
consumer:

- `internal/lifecycle/adapter.go` defines the control-plane `Adapter` contract
  over provider-neutral protocol types (`Kind`, `Discover`, `Rotate`, and
  `Retire`). The same file defines optional `Provisioner`, `VaultStore`, and
  `OneTimeSecretor` capabilities used for real provisioning and delivery.
- `internal/provider/multicloud.go` defines the structurally compatible
  `CloudAdapter` that `MultiProvider` composes and routes by
  `ProviderBinding.provider`.
- `internal/provider/vault.go` defines the optional `CloudVault` and
  `OneTimeSecretor` capabilities for provider-native delivery. Store methods
  return redacted references only; they must not put credential values in
  protocol objects, events, snapshots, logs, or errors.

An adapter author should validate required configuration in its constructor,
pass `context.Context` to provider calls, return conformant identities and
rotation evidence, make retries/cancellation explicit, and keep provider SDK or
wire details out of the lifecycle and frontend packages. Tests should cover
successful and failed discovery, rotation, retirement, confirmation-sensitive
behavior, provider-not-found/idempotent cleanup, and secret redaction.

A reusable conformance suite for external adapter authors is **planned**; no
separate third-party conformance package has shipped in this release.

## References

- `docs/protocol.md` — the provider-neutral wire contract and the per-provider
  `ProviderBinding` field conventions.
- `docs/security-model.md` — credential handling, blast radius, and redaction.
- `docs/azure-integration.md` — the reference interactive extension and its
  trust-boundary notes.
- `pkg/protocol/models.go` — the `ProviderBinding` Go type and source comments.
- `internal/provider/` — real and simulated adapters plus the multi-cloud
  composite.
- `internal/lifecycle/adapter.go` — the `Adapter` interface the control plane
  consumes.
- `internal/provider/vault.go` — the optional native-vault boundary.