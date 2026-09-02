# The public live demo (real tenants, zero permissions)

Since 2026-09-02 the public demo at `mutandae.com` (and `preview.mutandae.com`)
points at three **real** tenants — Azure / Entra, AWS IAM, and GCP IAM — instead
of a simulator. Visitors can create a genuine machine identity in each tenant,
rotate it, and retire it, all with **zero underlying permissions**. The whole
thing is bounded and throttled so no visitor can do real damage or grow the
tenants without bound.

This document explains the safety model, the exact least-privilege credentials
the server holds on each cloud, and how run them/verify them.

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
| Create | Yes | zero-permission identity + one-time secret returned exactly once |
| Rotate | Yes | new key/secret; old one revoked |
| Retire | Yes (after confirm) | AWS/IAM keys deleted; GCP SA keys deleted; Azure app deleted |
| Attach permissions | No | blocked by IAM boundary + adapter guard |
| Touch non-demo identities | No | demo-only mode lists/refuses anything outside `mutandae-demo-*` |

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
- **One-time secrets**: created secrets are returned in the single HTTP
  response only; they are never persisted in Redis, snapshots, events, logs, or
  HTML (verified by `TestAPIProvisionReturnsOneTimeSecretAndDoesNotPersistIt`
  and the real-cloud `no-secret` harness tests).

## Where the credentials live

The cloud credentials are stored in the Kubernetes **Secret**
`mutandae-provider-credentials` in the `mutandae` namespace (created
imperatively, never committed). The Deployment reads them via `secretKeyRef`
(`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `GCP_SERVICE_ACCOUNT_KEY_JSON`,
`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, …). The live
`MUTANDAE_ENVIRONMENT=live` container **fails to start** if any third credential
set is missing — there is no silent fall back to a simulator.

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