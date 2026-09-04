# The public live demo (real tenants, zero permissions)

Since 2026-09-02 the public demo at `mutandae.com` (and `preview.mutandae.com`)
points at three **real** tenants — Azure / Entra, AWS IAM, and GCP IAM — instead
of a simulator. Visitors can create a genuine machine identity in each tenant,
rotate it, use it, and retire it, all with **zero underlying permissions**. The
whole thing is bounded and throttled so no visitor can do real damage or grow
the tenants without bound.

This document explains the safety model, the exact least-privilege credentials
the server holds on each cloud, the vault delivery flow behind the **New
identity** button, and how to run/verify them.

## The core safety guarantee

> The server's cloud credentials are **least-privilege at the IAM level**. That
> guarantee holds even if the demo application is fully compromised. The UI and
> the adapters add a second, defense-in-depth namespace guard on top.

An external visitor can only ever cause the server to perform the operations the
server's own credentials can do. For each cloud those operations are exactly
"create a zero-permission identity and manage (rotate/retire) that identity's
keys/credentials." Nothing else. Attaching a policy, granting a role, adding to
a group, and granting admin consent are **not permitted to the demo credentials
even in principle**, so no amount of API abuse can escalate.

## Per-cloud demo governor principals (all free)

### AWS — IAM user `mutandae-governor` (account `572030963802`)

Inline policy (`mutandae-demo-scope`):

- Account-wide, read-only discovery: `iam:ListUsers`, `iam:GetUser`,
  `iam:ListAccessKeys`.
- Scoped to `arn:aws:iam::572030963802:user/mutandae-demo-*` only:
  `iam:CreateUser`, `iam:CreateAccessKey`, `iam:DeleteAccessKey`,
  `iam:DeleteLoginProfile`, `iam:DeleteUser`, `iam:TagUser`.

It is **explicitly denied** (not granted): `iam:AttachUserPolicy`,
`iam:PutUserPolicy`, `iam:AddUserToGroup`, `iam:CreateLoginProfile`,
`iam:CreateRole`, `iam:AttachRolePolicy`, `iam:PutRolePolicy`, `iam:PassRole`,
`iam:CreatePolicy`. So a created `mutandae-demo-*` user is a zero-policy user —
it can do nothing on its own.

### GCP — service account `mutandae-governor` (project `mutandae-demo`)

Custom project-level role `mutandaeDemoSaAdmin` grants only:
`iam.serviceAccounts.list`, `.get`, `.create`,
`iam.serviceAccountKeys.list`, `.create`, `.delete`, `.disable`, `.enable`,
`.get`.

It does **not** grant `resourcemanager.projects.setIamPolicy` or
`iam.serviceAccounts.setIamPolicy` (or any `roles/*` binding), so a newly
created `mutandae-demo-*` service account has no roles and cannot do anything.

### Azure / Entra — app registration `mutandae-eval`

The server holds client credentials for app `f207d334-1030-4d60-b7c2-06c6f2e422c0`
(tenant `ee37cc75-...`), which has only two Microsoft Graph **application
permissions**, both admin-consented:

- `Application.ReadWrite.All` (needed to create applications under app-only).
- `Application.ReadWrite.OwnedBy`.

It is **not** granted `AppRoleAssignment.ReadWrite.All` (so it cannot assign API
permissions to apps) and cannot perform tenant admin consent (requires Global
Admin). A created `mutandae-demo-*` application therefore has no API permissions
and no consent — a pure shell.

## What the demo can and cannot do to a created identity

| Action | Allowed | Result |
| --- | --- | --- |
| Create (New identity button + type dropdown) | Yes | zero-permission identity + one-time secret returned exactly once + secret delivered to the selected cloud's native vault |
| Use (✦ action) | Yes | credential retrieved from the vault; the retrieval is logged as `credential.used` with the vault reference |
| Rotate | Yes | new key/secret; old one revoked; new secret version written to the same vault |
| Retire | Yes (after confirm) | AWS/IAM keys deleted; GCP SA keys deleted; Azure app deleted; vault copy disabled/deleted |
| Attach permissions | No | blocked by IAM boundary + adapter guard |
| Touch non-demo identities | No | demo-only mode lists/refuses anything outside `mutandae-demo-*` |

## The New identity flow and vault delivery

The dashboard and the configuration page render a **New identity** button with
an identity-type dropdown (Azure / Entra ID, AWS IAM, GCP IAM — all three are
wired). One click:

1. creates the real zero-permission identity in the selected tenant,
2. writes the freshly issued credential into that cloud's **native vault** —
   AWS Secrets Manager for `aws-iam`, GCP Secret Manager for `gcp-iam`, Azure
   Key Vault for `azure-entra`,
3. records a `credential.delivered` audit event carrying only the vault name,
   version, and key id,
4. and returns the one-time secret in that single HTTP response as before.

Because the credential now lives in the vault, it is **viewable on the demo
site more than once**: the inventory's ✦ (Use) action retrieves the current
version from the vault and logs the retrieval as `credential.used`. Renewals
write a fresh version to the same vault; retirement disables the vault copy
(`credential.revoked`) so no usable credential outlives its identity.

The control plane still never persists secret values: Redis snapshots, events,
logs, and HTML carry vault references only. The vault copy lives entirely on
the visitor's selected cloud, holds the credential of a zero-permission
demo identity, and is revocable from the same UI.

### Vault credentials the server holds (additive to the IAM boundary)

Vault delivery is on by default (`MUTANDAE_VAULT=off` disables it globally).
The governor principals need these extra, namespace-scoped permissions:

- **AWS** — the `mutandae-demo-scope` inline policy gains, scoped to
  `arn:aws:secretsmanager:<region>:572030963802:secret:mutandae-demo-*`:
  `secretsmanager:CreateSecret`, `secretsmanager:PutSecretValue`,
  `secretsmanager:GetSecretValue`, `secretsmanager:DescribeSecret`,
  `secretsmanager:TagResource`, `secretsmanager:DeleteSecret`.
  **Status: pending operator action** — apply with an admin session
  (`aws login`) using the copy-paste policy below; until then AWS native
  delivery surfaces an honest attention `credential.delivered` event while
  the cluster μVault copy still works.
- **Azure** — the `mutandae-eval` application gains the **Key Vault Secrets
  Officer** role on the demo vault referenced by `AZURE_KEY_VAULT_URL`
  (provisioned as `mutandae-demo-kv-7f3a` in `mutandae-demo-rg`, westus2,
  RBAC-authorized; the role is assigned to the service principal object id
  `f6dd3b2d-e7ac-4853-a7a9-e35216a3bc68`). Graph permissions do not grant
  vault access, so this role is the only new grant.
  **Status: applied and verified** — live provisioning delivers to the
  vault and `Use` retrieves from it under audit.
- **GCP** — the `mutandae-governor` service account holds the custom project
  role `mutandaeDemoSecretManager` with `secretmanager.secrets.create`,
  `secretmanager.secrets.get`, `secretmanager.versions.add`,
  `secretmanager.versions.get`, `secretmanager.versions.access`,
  `secretmanager.versions.list`, `secretmanager.versions.disable`, hardened
  with an IAM condition `resource.name.startsWith("projects/<project-number>/secrets/mutandae-demo-")`
  (note: conditions use the project **number**, not the `_` placeholder, and
  the Secret Manager API must be enabled in the project — both applied).
  **Status: applied and verified.** GCP identity names are service-account
  emails, so the adapter derives a deterministic Secret-Manager-safe secret
  id from the identity name.
- **Cluster μVault** — the control plane also mirrors every demo credential
  into the cluster-local HashiCorp Vault (KV v2, path prefix
  `mutandae/demo/<environment>/…`) using a token scoped to the
  `mutandae-demo` policy. See [Cluster μVault runbook](#cluster-μvault-runbook).
  The application token can only create/read/delete secrets under that
  prefix; it is stored in the `mutandae-provider-credentials` Secret alongside
  the cloud credentials and is never committed to git.

The vault boundary does not weaken the core guarantee: these permissions can
only create/read/delete secrets under the `mutandae-demo-*` namespace, and the
only values ever stored are the zero-permission credentials of demo identities
themselves.

#### Applying the AWS grant (governor `mutandae-governor`, account `572030963802`)

```sh
# Re-authenticate first: aws login
aws iam put-user-policy --user-name mutandae-governor --policy-name mutandae-demo-scope --policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadOnlyDiscovery",
      "Effect": "Allow",
      "Action": ["iam:ListUsers", "iam:GetUser", "iam:ListAccessKeys"],
      "Resource": "*"
    },
    {
      "Sid": "DemoIdentityLifecycle",
      "Effect": "Allow",
      "Action": [
        "iam:CreateUser", "iam:CreateAccessKey", "iam:DeleteAccessKey",
        "iam:DeleteLoginProfile", "iam:DeleteUser", "iam:TagUser"
      ],
      "Resource": "arn:aws:iam::572030963802:user/mutandae-demo-*"
    },
    {
      "Sid": "DemoVaultDelivery",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:CreateSecret", "secretsmanager:PutSecretValue",
        "secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret",
        "secretsmanager:TagResource", "secretsmanager:DeleteSecret"
      ],
      "Resource": "arn:aws:secretsmanager:*:572030963802:secret:mutandae-demo-*"
    },
    {
      "Sid": "ExplicitDenyPrivilegeEscalation",
      "Effect": "Deny",
      "Action": [
        "iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:AddUserToGroup",
        "iam:CreateLoginProfile", "iam:CreateRole", "iam:AttachRolePolicy",
        "iam:PutRolePolicy", "iam:PassRole", "iam:CreatePolicy"
      ],
      "Resource": "*"
    }
  ]
}'
```

#### Applying the GCP grant (governor `mutandae-governor@mutandae-demo`)

```sh
gcloud services enable secretmanager.googleapis.com --project=mutandae-demo

gcloud iam roles create mutandaeDemoSecretManager --project=mutandae-demo \
  --title="Mutandae demo secret delivery" \
  --permissions=secretmanager.secrets.create,secretmanager.secrets.get,secretmanager.versions.add,secretmanager.versions.get,secretmanager.versions.access,secretmanager.versions.list,secretmanager.versions.disable

gcloud projects add-iam-policy-binding mutandae-demo \
  --member="serviceAccount:mutandae-governor@mutandae-demo.iam.gserviceaccount.com" \
  --role="projects/mutandae-demo/roles/mutandaeDemoSecretManager"
```

Optionally harden the binding with an IAM condition
`resource.name.startsWith("projects/_/secrets/mutandae-demo-")`.

#### Applying the Azure grant (governor `mutandae-eval`)

```sh
az login
VAULT_ID=$(az keyvault show --name <demo-vault> --query id -o tsv)
az role assignment create \
  --assignee-object-id f207d334-1030-4d60-b7c2-06c6f2e422c0 \
  --assignee-principal-type ServicePrincipal \
  --role "Key Vault Secrets Officer" \
  --scope "$VAULT_ID"
# then store the vault URL in the deployment secret:
k3s kubectl -n mutandae patch secret mutandae-provider-credentials \
  -p '{"stringData":{"AZURE_KEY_VAULT_URL":"https://<demo-vault>.vault.azure.net/"}}'
k3s kubectl -n mutandae rollout restart deploy/mutandae
```

Until the grants are applied, the demo stays honest: provisioning succeeds,
the audit trail carries an attention `credential.delivered` event naming the
failure, and the provision result shows the explicit "no vault copy" state.

### Vault environment variables

| Variable | Default | Effect |
| --- | --- | --- |
| `MUTANDAE_VAULT` | `auto` | `off` disables vault delivery everywhere. |
| `AZURE_KEY_VAULT_URL` | unset | Enables azure-entra delivery against this vault (`https://mutandae-demo-kv-7f3a.vault.azure.net/` in the live deployment). |
| `AZURE_KEY_VAULT_PREFIX` | `mutandae` | Key Vault secret-name namespace prefix. |
| `VAULT_ADDR` | unset | Enables cluster μVault mirroring when set together with `VAULT_TOKEN`. |
| `VAULT_TOKEN` | unset | Token for the cluster μVault, scoped to the `mutandae-demo` policy. |
| `VAULT_SECRET_PREFIX` | `demo` | Path prefix inside the cluster μVault mount; the deployments use `demo/live` and `demo/preview`. |

AWS and GCP vault delivery activate with their real adapters, and Azure
Key Vault delivery activates with `AZURE_KEY_VAULT_URL`; the delivery result
is surfaced honestly in the UI (delivered version or an explicit "no vault
copy" warning) and audited either way. When `VAULT_ADDR` and `VAULT_TOKEN`
are set, every delivered credential is additionally mirrored into the cluster
μVault and audited with `vault_kind: cluster-mutandae-vault`; the inventory
shows both copies.

## Cluster μVault runbook

The common vault is a single-node HashiCorp Vault 1.21.4 StatefulSet
(`mutandae-vault-0`) with raft storage on a Longhorn PVC, deployed and
reconciled by Flux from the `belacca-gitops` repository. Credentials survive
pod restarts; the SOPS-managed unseal key plus the unseal sidecar re-open the
raft store automatically after a restart. Initialization is deliberately
manual so the raft store is never silently re-created:

```sh
# one-time initialization (records the unseal key share and root token)
k3s kubectl -n mutandae exec mutandae-vault-0 -c vault -- \
  vault operator init -key-shares=1 -key-threshold=1 -format=json
# store the unseal key SOPS-encrypted in belacca-gitops
# (clusters/belacca-production/mutandae/vault-secret.yaml); the sidecar
# unseals from it automatically after any restart
k3s kubectl -n mutandae exec mutandae-vault-0 -c vault -- \
  vault operator unseal <UNSEAL_KEY>
# engine, policy, and application token
k3s kubectl -n mutandae exec mutandae-vault-0 -c vault -- \
  env VAULT_TOKEN=<ROOT_TOKEN> vault secrets enable -path=mutandae kv-v2
k3s kubectl -n mutandae exec mutandae-vault-0 -c vault -- \
  env VAULT_TOKEN=<ROOT_TOKEN> vault policy write mutandae-demo -
# policy: create/update/read on mutandae/data/demo/* and read/delete on
# mutandae/metadata/demo/* — nothing else
k3s kubectl -n mutandae exec mutandae-vault-0 -c vault -- \
  env VAULT_TOKEN=<ROOT_TOKEN> vault token create \
  -policy=mutandae-demo -orphan -ttl=8760h
# then patch the mutandae-provider-credentials Secret with VAULT_TOKEN and
# restart the application deployments
```

Recovery is automatic: on a fresh pod the sidecar polls `vault status` and
unseals with the key share from the Secret. If the PVC is lost, the raft data
is gone and the initialization steps above are simply repeated. Rotate the
application token by creating a replacement and patching the Secret; revoke
the old token afterwards.

## Demo-only mode

When running the live demo the AWS and GCP adapters are constructed with
`DemoOnly: true`. Discovery only returns identities under the
`mutandae-demo-*` namespace, and Rotate/Retire refuse anything else. The
governors are deliberately named **outside** that namespace
(`mutandae-governor`, …) so they are never governed by the demo. Azure is always
name-scoped to `mutandae-demo-*`.

## Abuse controls

- **Per-client-IP throttle** (`internal/web/rate.go`): reads, mutations, and
  provisioning each have their own token bucket (loopback exempt for health
  probes and tests). Configure via `MUTANDAE_RATE_*` env vars.
- **Per-provider quota with auto-reclaim** (`internal/web/server.go`): at most
  `MUTANDAE_DEMO_LIMIT` (default 40) active demo identities per provider; the
  oldest is retired (keys deleted) before a new one is created, keeping tenant
  growth bounded forever.
- **One-time secrets from the control plane**: provisioned secrets are
  returned in the single HTTP response only; they are never persisted in
  Redis, snapshots, events, logs, or HTML (verified by
  `TestAPIProvisionReturnsOneTimeSecretAndDoesNotPersistIt` and the real-cloud
  `no-secret` harness tests). The vault delivery feature adds exactly one
  durable copy — on the selected cloud's native vault, audited via
  `credential.delivered`/`credential.used`/`credential.revoked` events that
  carry references only — and the Use action can surface that vault copy in
  HTML on demand. Every such retrieval is rate-limited and audited.

## Where the credentials live

The cloud credentials are stored in the Kubernetes **Secret**
`mutandae-provider-credentials` in the `mutandae` namespace (created
imperatively, never committed). The Deployment reads them via `secretKeyRef`
(`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `GCP_SERVICE_ACCOUNT_KEY_JSON`,
`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, …). The live
`MUTANDAE_ENVIRONMENT=live` container **fails to start** if any third credential
set is missing — there is no silent fall back to a simulator.

## The demo vault (retrieve under audit)

Every provisioned or renewed credential is mirrored into the **cluster μVault**
(a HashiCorp Vault KV v2 server running in the demo namespace). The one-time
secret is still disclosed exactly once in the provision response; the vault
copy is what makes later retrieval possible:

- **Retrieve**: the inventory's labeled *Retrieve* action (and
  `POST /api/v1/identities/{id}/use`) reads the current version from the vault.
  Every retrieval is audited as `credential.used` with the vault reference and
  actor — never secret material.
- **Rotate**: writes a fresh version of the same vault secret, so consumers of
  an old version are never stranded.
- **Retire**: revokes the vault copy; retrieval then fails closed.

Provider-native vaults stay optional. Azure's Key Vault works out of the box
for the demo (the governor has the data-plane role). AWS Secrets Manager and
GCP Secret Manager are enabled in configuration but the governors deliberately
hold no such permissions; a deterministic authorization denial is treated as
"capability absent in practice": delivery skips silently, reads fall back to
the cluster μVault, and genuine vault outages still surface as attention
events without silently switching vaults.

## Verification

- Unit: `internal/provider/create_test.go` proves the AWS and GCP create paths
  never issue a privilege-granting call, and that `DemoOnly` Discovery filters
  and refuses non-demo identities.
- Unit: rate limiter and provisioning redaction tests in `internal/web`.
- Empirical (done on the real tenants): the governor can create a demo
  user/SA/app and rotate/retire it, and **cannot** attach an admin policy or
  grant a role (both returned `AccessDenied`/`PermissionDenied`).

```sh
# Re-verify the AWS boundary as the governor
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
aws iam attach-user-policy --user-name mutandae-demo-x \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess  # => AccessDenied
```

```sh
# Re-verify the GCP boundary as the governor
gcloud auth activate-service-account mutandae-governor@mutandae-demo.iam.gserviceaccount.com \
  --key-file=/path/to/key.json
gcloud projects add-iam-policy-binding mutandae-demo \
  --member="serviceAccount:mutandae-demo-x@mutandae-demo.iam.gserviceaccount.com" \
  --role=roles/viewer                                        # => PermissionDenied
```