# Security model

This document describes the security properties and limits of the published
Mutandae release. It is an operator guide, not a claim that the demo is an
authenticated enterprise control plane.

## Trust model

Mutandae is a control plane above cloud IAM and secret managers. It observes
provider identities, stores provider-neutral lifecycle metadata, and asks a
provider adapter to perform narrowly defined lifecycle operations. It does not
replace the provider's IAM policy, tenant authorization, network boundary, or
secret-manager access policy.

The process is trusted to hold the configured governor credentials and to keep
provider-specific execution behind the adapter boundary. Anyone who can invoke
the HTTP surface can ask the configured process to perform whatever operations
that process is authorized to perform, subject to the adapter's namespace
checks, rate limits, and confirmation requirements. Those controls are
important defense in depth, not a replacement for cloud IAM or HTTP
authentication.

## What Mutandae stores

The control plane stores protocol metadata, not plaintext provider secrets. A
snapshot or lifecycle event may contain:

- identity names, provider bindings, tenant/account/project references, and
  ownership metadata;
- lifecycle state, policy, expiry, key IDs, fingerprints, and rotation evidence;
- `CredentialReference` and `VaultReference` values such as a provider URI,
  vault name, secret name, and version; and
- lifecycle events, operation receipts, and rotation-run status.

It does **not** intentionally persist client secrets, AWS secret access keys,
GCP private-key material, Graph bearer tokens, or generated credential text in
those objects. A freshly issued value can exist briefly in adapter process
memory while it is handed to the one-time response and/or a configured vault.

Plaintext credential destinations are deliberately explicit:

1. The provider API returns newly generated material only at the create/rotate
   operation. The API response can disclose that value once to the caller.
2. If enabled and authorized, the provider-native vault stores the value:
   Azure Key Vault, AWS Secrets Manager, or GCP Secret Manager.
3. If configured, the cluster-local μVault (HashiCorp Vault KV v2) mirrors the
   value so it can be retrieved and audited later.
4. A deliberate `use` operation reads a vault copy and returns the current
   value to its caller. The retrieval is rate-limited and creates an audit
   event containing a reference, never the value.

Mutandae is therefore not a universal secret store, but a deployment that
turns on vault delivery does create durable plaintext copies in those vaults.
Configure their IAM/RBAC policies accordingly.

## Compromise meaning by backend

| Compromised component | What an attacker can learn or do | Required operator response |
| --- | --- | --- |
| Redis | Protocol snapshots, credential references, lifecycle events, rotation evidence, and pub/sub invalidations. Secret values are not expected there. | Treat identity metadata and audit data as exposed; rotate provider credentials if application or Redis access could also reach the process. |
| Provider-native or cluster μVault | Delivered credential values, vault versions, and paths for identities stored there. | Treat every delivered credential in the affected namespace as compromised; revoke/rotate it and investigate the vault policy and token. |
| Process environment / workload Secret | The configured governor credentials, including cloud API keys, service-account key material, and vault tokens. | Assume the process can mutate every resource those credentials and adapter guards permit; revoke the credentials, inspect provider audit logs, and replace the workload Secret. |
| Unauthenticated HTTP listener | An external caller can submit reads and lifecycle mutations as the configured operator. | Stop exposure, bind privately or enforce a trusted proxy boundary, review audit events, and rotate anything affected. |

A Redis compromise is not equivalent to a process compromise. Redis contains
references and audit state; the process environment contains the credentials
that authorize provider and vault calls.

## Secret redaction guarantees

For ordinary lifecycle output, Mutandae keeps provider secret material out of
events, Redis snapshots, operation receipts, logs, dashboard/configuration/audit
HTML, and normal JSON API responses. This includes client secrets, AWS secret
access keys, GCP private keys, Graph tokens, and generated secret text.

The one-time create/provision response and the explicit vault-backed `use`
response are intentional exceptions: they return a credential to the caller
who requested it. They are not persisted in snapshots or audit records. The
HTML provisioning result is likewise the documented one-time handoff; ordinary
inventory, audit, and configuration HTML must not contain the value.

This boundary is enforced by tests rather than by documentation alone:

- `internal/eval/harness_test.go` defines `assertNoSecrets` and checks real
  discovery/list/rotate/retire responses, dashboard HTML, configuration HTML,
  identity-list HTML, and captured web logs. Its
  `TestRealCloudWebLogsContainNoSecrets` test scans the log stream.
- `internal/eval/azurereal_test.go` runs the Azure integration extension and
  checks requirements, connection, application, one-time secret, receipt,
  invalidation, and disconnect responses. It separately asserts that the
  one-time secret is absent from the receipt.
- `internal/web/e2e_test.go` (`TestEndToEndVisitorJourney`) checks that
  inventory, persisted snapshots, and audit fragments do not contain the
  one-time value, while also checking the deliberate one-time handoff and
  revoked retrieval path.
- `internal/web/provision_test.go`
  (`TestAPIProvisionReturnsOneTimeSecretAndDoesNotPersistIt`) checks the API
  response versus the stored identity and events. `internal/web/integration_test.go`
  and `internal/web/server_test.go` check that integration/configuration pages
  do not expose submitted credentials or unsafe runtime settings.
- Provider-level redaction tests in `internal/provider/azure_test.go`,
  `aws_test.go`, `gcp_test.go`, `gcpsecret_test.go`, and
  `hashicorpvault_test.go` cover provider tokens, signing material, generated
  secrets, and vault error messages.

These tests reduce accidental disclosure; they do not protect a vault that is
misconfigured or an already-compromised process memory space.

## Authentication posture today

The HTTP surface is **unauthenticated by default**. That is intentional for
the local and hosted demo. It is rate-limited by client IP for reads,
state-changing requests, and provisioning; loopback is exempt for health probes,
local development, and tests. Rate limiting is an abuse control, not identity,
authorization, or tenant isolation.

An authentication and authorization mode using OIDC, API tokens, and RBAC
**ships in this release** (`MUTANDAE_AUTH_MODE=oidc|token`). The hosted public
demo deliberately runs with `MUTANDAE_AUTH_MODE=none`: it is rate-limited by
client IP and scoped to the synthetic `mutandae-demo-*` namespace, and open
access is the point of the demo. A live deployment with `auth=none` emits a
loud startup warning. Until you enable an auth mode or put the listener behind
a boundary that enforces identity:

- bind local use to `127.0.0.1` or a private interface;
- put any shared deployment behind a VPN or a trusted reverse proxy with SSO;
- do not publish the listener directly to the internet; and
- keep cloud credentials scoped to disposable demo/evaluation namespaces.

Do not infer authentication from an `X-Mutandae-Operator` value or any other
client-supplied label. Such fields provide correlation metadata only.

## Operator blast radius

Every state-changing action requires a deliberate operator request. `retire`
requires a JSON `confirm: true`; permanent `delete` requires `confirm: true` and
only accepts an identity already in the retired state. The dashboard also uses
an explicit browser confirmation for destructive controls.

| Action | Azure/Entra ID | AWS IAM | GCP IAM | Control-plane result |
| --- | --- | --- | --- | --- |
| Rotate | Creates a new application password credential and removes the prior one. | Creates a new IAM user access key and removes the prior key, respecting AWS's two-key ceiling. | Creates a new user-managed service-account key and removes the prior key, respecting the ten-key ceiling. | New key ID/fingerprint and a correlated rotation run; a configured vault receives a new version. |
| Retire (`confirm: true`) | Deletes the demo application registration from Graph. | Deletes the user's access keys and best-effort deletes a console login profile. | Deletes all user-managed keys; the service account itself remains for provider-side cleanup. | Marks the governed record retired, revokes configured vault copies, and preserves the retired audit record in the control-plane store. |
| Delete (`confirm: true`, retired only) | No additional provider mutation. | No additional provider mutation. | No additional provider mutation. | Permanently removes the retired identity, its events, and rotation runs from the control-plane store after returning final terminal evidence. This is not undo and does not recreate provider objects. |

The real adapters add namespace guards in demo mode. Demo provisioning and
mutation are restricted to `mutandae-demo-*`. For AWS and GCP evaluation, the
harness uses the non-secret `MUTANDAE_EVAL_PREFIX` (default
`mutandae-eval`) as its mutation allow-list and leaves other discovered
identities read-only; the Azure evaluation uses disposable in-memory targets or
its documented demo namespace. Cloud IAM/RBAC remains the outer allow-list:
use only credentials that can list and mutate the intended tenant,
account/project, and namespace. Do not grant broad administrator permissions
merely to make an evaluation pass.

## Evaluation credential hygiene

Follow section 6 of [integration-testing.md](integration-testing.md):

- use short-lived, disposable credentials and never put values in this
  repository, issues, screenshots, shell history, or logs;
- pass secrets through environment or an external secret mechanism, not source
  or command arguments where they can enter process listings;
- use the least-privileged Azure, AWS, and GCP permissions listed by the
  integration document;
- scope AWS and GCP test identities to the `mutandae-eval-*` namespace or its
  equivalent; and
- invalidate generated keys, temporary client secrets, consent, service
  accounts, and test principals after evaluation. Treat any leaked value as
  compromised and rotate it immediately.

The real-cloud harness is opt-in and can create, rotate, and retire resources.
Review the target scope and provider audit logs before running it.
