# GCP IAM integration

Mutandae models the Google Cloud IAM boundary with two representations:

1. A synthetic **GCP IAM simulator** whose inventory feeds the multi-cloud
   governance demo.
2. A **real-world integration** contract describing exactly what a caller must
   supply to evaluate a real GCP IAM integration with Mutandae.

This document intentionally does not ship a live Google Cloud client. Like the
AWS and Azure reflections, the GCP story here is honest about trust boundaries:
the operator and their IAM policy authorize each mutation; Mutandae never holds
service-account key material and cannot read a user-managed key's private key
back from Google Cloud after it is created.

## The simulated GCP IAM adapter

`internal/provider/gcpsimulator.go` models a single Google Cloud project with
service accounts, each owning a renewable service-account key. It mirrors the
Azure/Entra and AWS IAM simulators' structure: a fixed provider clock (`now`),
a mutex, a map keyed by service-account unique id, and a credential/key
sequence counter. The stable provider kind is `gcp-iam`.

The adapter is a `CloudAdapter` and is structurally compatible with the
lifecycle `Adapter` boundary, so the multi-cloud control plane can govern it
alongside the azure-entra and aws-iam adapters exactly like a single provider.

### Seeded service accounts

The simulator seeds exactly three service accounts (names chosen to not
collide with the azure-entra or aws-iam seed sets):

| service account | environment | team | service | criticality | seeded health | initial key id | expires |
|---|---|---|---|---|---|---|---|
| `inventory-broker` | production | Commerce Infrastructure | Stock reconciliation | high | attention | `inventory-broker-service-key-1` | +5 days |
| `ml-training-runtime` | staging | Data Engineering | ML training | high | healthy | `ml-training-runtime-service-key-2` | +18 days |
| `catalog-replication` | production | Commerce Infrastructure | Catalog sync | medium | healthy | `catalog-replication-service-key-3` | +75 days |

Each service account tracks a single renewable user-managed (user-downloadable)
JSON service-account key. Rotation replaces the seeded key with a fresh
`<name>-service-key-N` and advances a `sha256:<hex>` credential fingerprint.
Retirement disables the service account and hides it from a subsequent
discovery.

Every discovered identity conforms to `protocol.ValidateIdentity` (with the
control-plane governance `ID` assigned before validation), exposing:

- provider kind `gcp-iam`;
- credential kind `service_account_key`;
- credential location
  `iam://projects/<project_id>/serviceAccounts/<email>/keys/<key_id>`; and
- credential delivery `secret-manager`.

## Mapping GCP IAM identifiers into the protocol

GCP identifiers have a distinct shape from Entra object IDs or AWS account/user
IDs, so the adapter maps them with deliberate intent:

| GCP identity fact | example | protocol field |
|---|---|---|
| owning Google Cloud project id | `mutandae-demo` | `ProviderBinding.ProjectID` |
| region of the workload e.g. `us-central1` | `us-central1` | `ProviderBinding.Region` |
| service-account unique id (project-local numeric id) | `123456789012345678901` | `ProviderBinding.ProviderID` |
| service-account identifier (email) e.g. `<name>@<project>.iam.gserviceaccount.com` | `catalog-replication@mutandae-demo.iam.gserviceaccount.com` | `Ownership.Contacts` |
| cloud provider | `gcp-iam` | `ProviderBinding.Provider` |

The control plane never reads these internals; it correlates on the identity
`ID` it assigns. The service-account unique id is the provider-side opaque
identifier — the same way the Azure adapter uses the Entra object id and the
AWS adapter uses the IAM user name — so a rotation or retirement can be routed
back to the exact service account without needing GCP resource-name metadata at
the domain layer.

## Real-world integration

To evaluate a real GCP IAM integration with Mutandae, a caller supplies exactly
this configuration:

- **a Google Cloud project** `project_id` (e.g. `mutandae-demo`) that owns the
  target service accounts;
- **a region** (e.g. `us-central1`);
- a **location for the service-account JSON key credentials** sent to the
  consuming workload — e.g. Secret Manager or a JWT key store (referenced here
  as `JWT keys`);
- and a least-privilege IAM permission set for the control-plane service
  principal covering exactly:

```text
iam.serviceAccounts.list
iam.serviceAccounts.get
iam.serviceAccounts.keys.list
iam.serviceAccounts.keys.create
iam.serviceAccounts.keys.delete
iam.serviceAccounts.keys.disable
```

### Recommended role

Google recommends the IAM role `roles/iam.serviceAccountKeyAdmin`
(`Service Account Key Admin`) for a principal that manages service-account
keys. Recipes that need to modify the service accounts themselves (rather than
only their keys) additionally need `roles/iam.serviceAccountAdmin`. The former
covers the permission set above; the latter is not required solely to rotate or
revoke keys.

### Key model and rotation

Service-account keys are associated with a service-account **identifier** — the
email of the form `<name>@<projectID>.iam.gserviceaccount.com`, not with a
human or a workload directly. A service account may hold multiple keys, but
only **user-managed keys** can be created/deleted via the IAM API; these are the
only keys downloadable as JSON, so the demo simulates a single active
user-downloadable key per service account. Rotation creates a new key while the
old one is still valid, hands the new key to the consuming workload, verifies
it, then deletes (or disables) the old key.

### Secret handling trust boundary

Google Cloud returns a service-account key's private key material **only at
`iam.serviceAccounts.keys.create`** and never again. Without a Secret Manager
persisting the generated JSON key, the newly-created private key is shown
**once** at rotation time and the operator must copy it immediately; Mutandae
will not store it and Google cannot recover it later. This mirrors the one-time
show trust boundaries documented for AWS `CreateAccessKey` and Azure Graph
`secretText`.

The control-plane service principal's own service-account JSON key is
write-only and must never be placed into snapshots, events, logs, or HTML
templates. It must live in a location (e.g. `JWT keys` / Secret Manager) that
Mutandae references but in which it does not store secrets.

### What is honest and what is not

This section is a contract, not an implementation. The simulator models
lifecycle and audit outcomes honestly without containing production GCP
credentials or pretending to be a real Google Cloud client. Evaluating a real
integration requires the operator-supplied project id, region, key location,
and IAM permission set above, plus a review of the service-account policy
before any production workload is touched, exactly as the AWS and Azure
integration pages require for their clouds.