# AWS IAM integration

Mutandae models the AWS IAM boundary with two representations:

1. A synthetic **AWS IAM simulator** whose inventory feeds the multi-cloud
   governance demo.
2. A **real-world integration** contract describing exactly what a caller must
   supply to evaluate a real AWS IAM integration with Mutandae.

This document intentionally does not ship a live AWS client. Like the Azure
reflection, the AWS story here is honest about trust boundaries: the operator
and their IAM policy authorize each mutation; Mutandae never holds AWS secrets
and cannot read an access key's secret value back from AWS after it is created.

## The simulated AWS IAM adapter

`internal/provider/awssimulator.go` models an AWS account with IAM users, each
owning a renewable access key. It mirrors the Azure/Entra simulator's
structure: a fixed provider clock (`now`), a mutex, a map keyed by IAM user
name, and a credential sequence counter. The stable provider kind is
`aws-iam`.

The adapter is a `CloudAdapter` and is structurally compatible with the
lifecycle `Adapter` boundary, so the multi-cloud control plane can govern it
alongside the azure-entra adapter exactly like a single provider.

### Seeded IAM users

The simulator seeds exactly three IAM users (names chosen to not collide with
the azure-entra or gcp-iam seed sets):

| IAM user | environment | team | service | criticality | seeded health | initial access key id | expires |
|---|---|---|---|---|---|---|---|
| `orders-deployer` | production | Orders Platform | Order deployment | high | attention | `orders-deployer-infra-key` | +5 days |
| `data-exporting` | staging | Data Engineering | Export pipeline | high | healthy | `data-exporting-infra-key` | +18 days |
| `metrics-publisher` | production | Observability | Metrics publishing | medium | healthy | `metrics-publisher-infra-key` | +75 days |

Each user owns a single renewable access key. Rotation replaces the seeded
`<name>-infra-key` with `<name>-access-key-N` and advances a `sha256:<hex>`
credential fingerprint. Retirement disables the IAM user and hides it from a
subsequent discovery.

Every discovered identity conforms to `protocol.ValidateIdentity` (with the
control-plane governance `ID` assigned before validation), exposing:

- provider kind `aws-iam`;
- credential kind `access_key`;
- credential location `iam://<account_id>/user/<name>`; and
- credential delivery `secret-manager`.

## Mapping AWS IAM identifiers into the protocol

AWS IAM identifiers have a materially different shape than Entra object IDs or
GCP project/resource IDs, so the adapter maps them with deliberate intent:

| AWS identity fact | example | protocol field |
|---|---|---|
| owning AWS account id | `123456789012` | `ProviderBinding.AccountID` |
| region of the service principal e.g. `us-east-1` | `us-east-1` | `ProviderBinding.Region` |
| IAM user name | `orders-deployer` | `ProviderBinding.ProviderID` |
| cloud provider | `aws-iam` | `ProviderBinding.Provider` |

The control plane never reads these internals; it correlates on the identity
`ID` it assigns. The IAM user name is the provider-side opaque identifier — the
same way the Azure adapter uses the Entra object id — so that a rotation or
retirement can be routed back to the exact IAM user without needing AWS account
metadata at the domain layer.

## Real-world integration

To evaluate a real AWS IAM integration with Mutandae, a caller supplies exactly
this configuration:

- **AWS account id** (e.g. `123456789012`) that owns the IAM users;
- **a region** (e.g. `us-east-1`);
- **long-lived access key ID + secret access key** for the control-plane
  service principal (a dedicated IAM user, not a human or the target workload);
- and a least-privilege IAM policy for that principal covering exactly:

```text
iam:ListUsers
iam:ListAccessKeys
iam:CreateAccessKey
iam:UpdateAccessKey
iam:DeleteAccessKey
iam:DeleteLoginProfile
iam:GetUser
```

### Rotation model

AWS permits at most **two access keys per IAM user**. Rotation is therefore a
two-phase operation: create the new key while the old one is still active, hand
the new key to the consuming workload, verify it, then update/delete the old
key. Mutandae encodes that constraint in the rotation workflow rather than
issuing a single unconditional create/delete pair. `UpdateAccessKey` lets the
adapter make an access key `Inactive` before `DeleteAccessKey` removes it, and
`DeleteLoginProfile` removes a user's console password profile during
retirement.

### Secret handling trust boundary

AWS returns an access key's **secret access key only at `CreateAccessKey`** and
never again. Without a Secret Manager to persist the generated value, the
newly-created secret access key is shown **once** at rotation time and the
operator must copy it immediately; Mutandae will not store it and AWS cannot
recover it later. This mirrors the same one-time-show trust boundary that the
Azure integration documents for Graph `secretText`.

The service principal's own secret access key is write-only and must never be
placed into snapshots, events, logs, or HTML templates.

### What is honest and what is not

This section is a contract, not an implementation. The simulator models
lifecycle and audit outcomes honestly without containing production AWS
credentials or pretending to be a real AWS SDK client. Evaluating a real
integration requires the operator-supplied credentials above and a review of
their IAM policy before any production workload is touched, exactly as the
Azure integration page requires for Entra.