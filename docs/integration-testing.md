# End-to-end cloud integration-test evaluation

This document is the plan to evaluate that the μTandae Protocol contract and the
browser UI work end-to-end against **real provider APIs** on each of Azure/Entra,
AWS IAM, and GCP IAM, using the **same protocol shapes** everywhere. It is the
"what I need from you to be autonomous" contract: the credential/permission
inventory a reviewer must contribute for the evaluator to run the tests without
further back-and-forth.

The public demo ships a dependency-light composition (Go standard library only —
no cloud SDKs) plus one opt-in real client. Where real provider calls live, that
is stated explicitly below at the **adapter boundary**. Everything else is
provider-neutral protocol and an evaluator-provided test harness.

---

## 1. Goal

Verify, with an integration test that targets **real provider APIs**, that:

- the **μTandae Protocol** (`pkg/protocol`, served under `/api/v1`:
  `discovery`, `list`, `register`, `rotate`, `retire`) is honored against real
  identities returned by real provider adapters;
- the **browser UI** (HTML dashboard `/` and `/configuration`, plus the
  identity list) renders those provider-backed identities and lets an operator
  rotate and retire them; and
- the **interactive integration extension** (`/api/v1/integration/*`, Azure
  today) exercises real Entra operations without leaking secret material.

The correctness criterion is **provider-neutral conformance**: each cloud adapter
returns the same protocol `MachineIdentity`, emits the same lifecycle events,
and produces `RotationRun`/`CredentialReference` evidence. No cloud-specific
shape leaks into the protocol layer.

### Where the real provider calls live

- **Adapter boundary (the only place provider mechanics may exist):**
  `internal/lifecycle.Adapter` (`Kind`, `Discover`, `Rotate`, `Retire`) and the
  structurally-compatible `internal/provider.CloudAdapter`. The composite
  `internal/provider.MultiProvider` fans discovery across sub-adapters and routes
  `Rotate`/`Retire` by `ProviderBinding.provider`; it never knows provider
  mechanics.
- **Azure / Entra (real, in-tree):** `internal/provider/azure.go` holds real
  Microsoft Graph + Key Vault calls using only the Go standard library
  (`net/http`). It is exercised through the short-lived interactive integration
  session manager (`internal/lifecycle/integration.go`) behind `/api/v1/integration/*`.
- **AWS IAM and GCP IAM (real, in-tree):** `internal/provider/aws.go` implements SigV4 against the IAM Query API and `internal/provider/gcp.go` implements JWT-assertion REST calls against the IAM API, both using only the Go standard library (`net/http`) behind the same `Adapter`/`CloudAdapter` boundary. The simulated variants (`internal/provider/awssimulator.go`, `gcpsimulator.go`) stay for the demo and for credential-less unit tests; the harness swaps in the real adapters when live credentials are present.

The design intent is that the **evaluation harness** is composable: swap the simulated adapters for real adapters behind the same boundary, keep the protocol assertions identical, and the same checklist in section 5 passes on every cloud.

---

## 2. What is evaluated (checklist)

Protocol conformance (called against the running server):

- [ ] **Discovery returns v1.** `GET /api/v1/` returns an index with
  `api_version: "v1"` and the `application/vnd.mutandae.v1+json` media type,
  and lists `list`, `register`, `rotate`, `retire` relations.
- [ ] **List returns conformant identities.** `GET /api/v1/identities`
  (`list`) returns the real adapter's discovered identities, each validating
  against `ValidateIdentity` (required `id`, `name`, `provider.provider`,
  `provider.provider_id`, `ownership.team/service/purpose`, valid `state` and
  `health`).
- [ ] **Register adopts an identity.** `POST /api/v1/identities` adopting one
  of the discovered identities returns the identity with a `registered`/`active`
  state and records an `identity.registered` event.
- [ ] **Rotate correlates a RotationRun + events.** `POST /api/v1/identities/{id}/rotations`
  produces a `RotationRun` with `Status` `running` → `succeeded`, a
  `rotation.started` event followed by `rotation.completed`, a shared
  `correlation_id`, and a `RotationRun.evidence` `CredentialReference` carrying
  the provider's new key evidence (new `key_id`/`fingerprint`).
- [x] **Retire requires confirmation.** `POST /api/v1/identities/{id}/retire`
  without `confirm: true` is rejected (protocol `conflict`); with `confirm: true`
  it emits `identity.retired` and moves the identity to `state: retired`.
- [x] **The UI renders provider-backed identities.** The HTML dashboard
  (`/configuration` view, `internal/web/templates/index.html` + `identity-list.html`)
  renders, for each real identity, the **provider label** (`azure-entra` → "Azure
  / Entra ID", `aws-iam` → "AWS IAM", `gcp-iam` → "GCP IAM"), the **ownership**
  (team/service), **urgency** (healthy / expiring / overdue), **expiry**, and
  row-level **Rotate** / **Retire** controls (retire uses `hx-confirm`).
- [x] **The dashboard rotate/retire writes through to the real provider** and
  the refreshed list reflects the provider-observed state.

**Interactive integration extension (Azure today, evaluator-provided):** the
`/api/v1/integration/*` routes (`requirements`, `connect`, `session`,
`disconnect`, `applications` plus application-create via `POST
/api/v1/integration/applications`, `secrets`, `secrets/read`,
`secrets/invalidate`) connect with the supplied client credentials, list owned
applications, create an application, add a one-time client secret (returned only
by `addPassword`), and invalidate it, with a redacted Redis event receipt and
correlation ID on each operation.

---

## 3. Per-cloud credential + permission inventory

Each block is a **template of what the caller contributes**. No real secret value
is, or should be, embedded anywhere in this document, the codebase, or the issue.

### 3.1 Azure / Entra (`azure-entra`)

Required:

| Variable | Kind | Example / notes |
| --- | --- | --- |
| `AZURE_TENANT_ID` | non-secret | `00000000-0000-0000-0000-000000000000` |
| `AZURE_CLIENT_ID` | non-secret | application (client) GUID |
| `AZURE_CLIENT_SECRET` | **secret** | temporary client secret |

API permission the client needs (granted + admin-consented in the tenant) and what the evaluation verified against a real tenant (2026-09-02):

- `Application.ReadWrite.OwnedBy` (Microsoft Graph **application permission**).
  This is the ownership boundary: Graph only allows mutations on applications
  owned by the calling client, and allows `GET /applications`+`GET /servicePrincipals`
  to list the tenant. Under an app-only (client credentials) session this covers
  listing and managing applications the caller already owns.
- `Application.ReadWrite.All` (Microsoft Graph **application permission**), also
  required by app-only sessions to create brand-new applications: Graph rejects
  `POST /applications` under `OwnedBy` alone with `Authorization_RequestDenied`.
  Real-tenant verification also showed that Graph **cannot** attach a service
  principal as an application owner (`POST /applications/{id}/owners` → 400
  `Unsupported resource type 'DirectoryObject'`), so app-only sessions treat
  applications they created in-session as owned (a session creation grant), while
  every other application must list the calling client as a Graph owner.
  Interactive/delegated sessions can use `OwnedBy` alone for the full checklist.

Optional, to test secure secret retention:

- existing Key Vault URL (e.g. `https://<vault>.vault.azure.net`) + Key Vault
  data-plane role (`Key Vault Secrets Officer` and/or `Key Vault Secrets User`) on
  that vault, plus the client's object IDs to tag as owners.

Note for the test: **Microsoft Graph returns `secretText` only from `addPassword`**;
it cannot be read back later. Without a vault the evaluator must capture the
secret at creation (one-time). With a vault the evaluator keeps only the safe
`VaultReference` (name/version), never the secret.

### 3.2 AWS IAM (`aws-iam`)

| Variable | Value | Example |
| --- | --- | --- |
| `AWS_ACCOUNT_ID` | non-secret | 12-digit account ID |
| `AWS_ACCESS_KEY_ID` | non-secret (identifier) | `AKIA...` |
| `AWS_SECRET_ACCESS_KEY` | **secret** | long-lived key secret |
| `AWS_REGION` | non-secret | `us-east-1` |

IAM permissions required on the evaluation principal (list + rotate):

- `iam:ListUsers`, `iam:GetUser`
- `iam:ListAccessKeys`
- `iam:CreateAccessKey`, `iam:UpdateAccessKey`, `iam:DeleteAccessKey`
- optional `iam:DeleteLoginProfile`, `iam:TagUser` (for retire/metadata)

Rotation model to expect and assert: **AWS allows a maximum of 2 access keys per
IAM user.** Rotation must therefore create a new key, verify it, then
`DeleteAccessKey` the old one (or you hit the hard 2-key ceiling). Retirement is
`DeleteAccessKey` (and `DeleteLoginProfile` if present). Recommend running the
evaluation under a **scoped IAM policy / external-id-capable principal** so a test
failure cannot affect unrelated accounts; the identifiers in this document are
only inserted into the running process, never on the wire for long.

### 3.3 GCP IAM (`gcp-iam`)

| Variable | Value | Example |
| --- | --- | --- |
| `GCP_PROJECT_ID` | non-secret | e.g. `my-eval-project` |
| `GCP_REGION` | non-secret | e.g. `us-central1` |
| `GCP_SERVICE_ACCOUNT_KEY_JSON` | **secret** | service-account JSON **key file** (contains `private_key`) |

IAM role the test account needs (least privilege):

- `roles/iam.serviceAccountKeyAdmin`

or, equivalently, the individual `iam.serviceAccounts.*` permissions it grants:

- `iam.serviceAccounts.list`, `iam.serviceAccounts.get`
- `iam.serviceAccounts.keys.list`, `iam.serviceAccounts.keys.create`
- `iam.serviceAccounts.keys.delete`, `iam.serviceAccounts.keys.disable`

Note: prefer using **workload identity federation** as the long-term alternative
to long-lived service-account keys; for this evaluation the supplied JSON key is
accepted and invalidated/revoked afterward.

---

## 4. Environment variables / command matrix for the evaluation harness

Proposed configuration variables and what each holds, **clearly segregated
secret from non-secret**. Non-secret values may appear in config/logs; secret
values must never be echoed or committed.

### Non-secret (safe to log)

| Variable | Holds |
| --- | --- |
| `PORT` | HTTP port for the server under test (default `8080`) |
| `MUTANDAE_ENVIRONMENT` | label, e.g. `preview`, `ci-eval` |
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` | Entra tenant + client GUIDs |
| `AZURE_KV_URL`, `AZURE_KV_SECRET_PREFIX` | optional vault URL + prefix |
| `AWS_ACCOUNT_ID`, `AWS_REGION`, `AWS_ACCESS_KEY_ID` | AWS context + key id |
| `GCP_PROJECT_ID`, `GCP_REGION` | GCP project + region |

### Secret (never log, never commit)

| Variable | Holds |
| --- | --- |
| `AZURE_CLIENT_SECRET` | Entra client secret (temporary) |
| `AWS_SECRET_ACCESS_KEY` | AWS IAM key secret |
| `GCP_SERVICE_ACCOUNT_KEY_JSON` | GCP service-account private key JSON |

Suggested invocation flows:

```sh
# Azure integration extension end-to-end
go run ./cmd/mutandae &
curl -sS :8080/api/v1/                                # discovery → v1
curl -sS :8080/api/v1/identities                      # list
curl -sS :8080/api/v1/integration/requirements        # requirements (non-secret first)

# Rotate one discovered identity (real adapter)
curl -sS -X POST :8080/api/v1/identities/<id>/rotations -d '{"requested_by":"eval"}'

# Retire requires confirmation
curl -si -X POST :8080/api/v1/identities/<id>/retire            # expect 409
curl -si -X POST :8080/api/v1/identities/<id>/retire -d '{"confirm":true}'

# UI smoke test
curl -s :8080/configuration | grep -q 'μTandae'             # dashboard renders
```

Exactly where the real adapter is wired is the **composition root**
(`cmd/mutandae/main.go`): today it wires the `azure-entra` simulator plus the
interactive integration session. For the evaluation, the same root composes real
`azure-entra`, `aws-iam`, and `gcp-iam` adapters behind `MultiProvider`. The
evaluator documents that wiring in the harness; no other component changes.

---

## 5. Acceptance / verification checklist per cloud

Run once per cloud; all must pass.

- [x] **Discovery** returns `api_version: "v1"` and a `list` relation.
- [x] **List adoption** — `GET /api/v1/identities` returns the discovered real
      identities (AWS IAM users, GCP service accounts, Azure/Entra identities),
      each conformant and with the correct `provider`.
- [x] **Rotate** — `POST .../rotations` returns an identity whose
      `credential.key_id` and `credential.fingerprint` changed from the
      discovered value; a correlated `rotation.started` → `rotation.completed`
      pair with a matching `correlation_id`; `RotationRun.status` endstate
      `succeeded`. (Azure: Graph key id; AWS: new access-key id; GCP: new key id
      + fingerprint.)
- [x] **Retire** — confirmation-less request returns `conflict/409`; confirmed
      request transitions to `state: retired`, emits `identity.retired`, and the
      provider-side credential is invalidated/deleted (AWS key + login profile
      deleted; GCP key deleted; Entra password revoked).
- [ ] **Retire can restore/hide** — the retired identity disappears from the
      active list (`list` hides or marks `retired`) without deleting the audit
      trail. (Adapters skip zero-credential identities on the next `Discover`,
      but the harness does not yet assert the re-listed view; left for a follow-up.)
- [x] **UI** — dashboard shows `provider` label (e.g. "AWS IAM"), ownership,
      urgency, expiry, and working Rotate / Retire from the dashboard; the list
      refreshes with provider state.
- [x] **Azure-only**: `addPassword` returns a usable secret once
      (`key_id` + secret_text), invalidation revokes it, and the redacted
      receipt never exposes the secret text. (Vault-path verification requires a
      configured Key Vault and is exercised separately in `docs/azure-demo.md`.)
- [x] **No secret in output** — no `client_secret`, AWS secret, GCP private
      key, Graph token, or emitted secret text appears in ANY lifecycle event,
      snapshot, integration receipt, log, or HTML render.

---

## 6. Security notes

- Represent secrets only as environment/template placeholders here. **Never paste
  real credentials into the issue, this doc, screenshots, shell history, or logs.**
- Use **expiring, short-lived** credentials for the evaluation (the integration
  session itself is in-memory and short-lived, ~10 min TTL, and holds credentials
  only inside the active provider client).
- **Invalidate/revoke after the test:**
  - Azure: invalidate the generated application credentials and the temporary
    `client_secret`; remove admin consent if the client is no longer used.
  - AWS: delete the created/rotated access keys and the evaluation IAM principal.
  - GCP: disable/delete the rotated keys and retire/delete the test service account.
- If the repo is open/public, use **ephemeral secrets** and drive automation from
  seeds (`.env.example`, CI input variables, secret env) that are **never
  committed**; treat any leaked value as compromised and rotate immediately.
- Mutandae already keeps secrets out of snapshots/events/logs by design (see
  `docs/azure-integration.md`); the acceptance checklist above re-verifies that
  for every cloud adapter.
## 7. Evaluation results (2026-09-02)

Executed against live AWS (account `572030963802`, IAM), GCP (project
`mutandae-eval`), and Azure / Entra (tenant `ee37cc75-...`, Microsoft Graph)
with disposable evaluation principals:

```sh
MUTANDAE_EVAL=1 go test -tags=realclouds -count=1 -v ./internal/eval/...
```

All real-cloud tests pass: `TestRealCloudDiscoveryReturnsV1`,
`TestRealCloudListReturnsConformantIdentities`,
`TestRealCloudRotateAndRetire` (aws/gcp/azure subtests),
`TestRealCloudUIRendersProvidersAndControls`,
`TestRealCloudWebLogsContainNoSecrets`, and
`TestAzureRealIntegrationExtension`. No secret value appeared in any event,
snapshot, receipt, log, or HTML render.

Real-tenant findings that shaped the adapters:

- **AWS `ListUsers` omits tags; `GetUser` returns them.** The AWS adapter now
  resolves each user with `GetUser` (`getUser`) to map `MUTANDAE_*` ownership
  tags honestly (`internal/provider/aws.go`). `ListUsers` keeps pagination.
- **SigV4 canonical URI must be `/` for the IAM endpoint** (empty path
  normalizes to `/`); the unit fake previously only checked the header format,
  so a real-signed request failed with `SignatureDoesNotMatch`. The regression
  test `TestSignV4OfficialVector` pins the official aws-sig-v4-test-suite
  `get-vanilla` vector (`Signature=5fa00fa3...`).
- **GCP key creation requires `keyAlgorithm: KEY_ALG_RSA_2048`** (not the
  aliased `..._2048_4096`), or IAM rejects with `INVALID_ARGUMENT`.
- **Azure app-only creation needs `Application.ReadWrite.All`.** Under
  client credentials, `POST /applications` with `OwnedBy` only returns
  `Authorization_RequestDenied`; and Graph cannot attach a service principal as
  an application owner (`Unsupported resource type 'DirectoryObject'`). The
  adapter therefore records a session creation grant for apps it created, and
  the requirements contract warns about the app-only permission split.
- **Microsoft Entra directory writes replicate asynchronously**; mutations
  against a just-created application can 404 (`Request_ResourceNotFound`) or
  race removals (`No password credential found with keyId`) for seconds. The
  Azure adapter performs a bounded read-your-write poll after application
  creation and retries idempotent removals; the GCP adapter retries transient
  transport failures on GET/DELETE.
- **GCP budget/alert and eval credential hygiene:** eval principals were
  scoped to the `mutandae-eval-` prefix (`iam:Create/Update/DeleteAccessKey`,
  `iam:DeleteLoginProfile`, `iam:TagUser` under
  `user/mutandae-eval-*`; GCP custom role `mutandaeEvalKeyAdmin`). All eval
  keys are disposable; after the evaluation is closed they should be revoked
  and the principals deleted per section 6.
