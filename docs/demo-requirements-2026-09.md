# Demo upgrade requirements — September 2026

This document organizes the 2026-09 demo upgrade requirements, the decisions
behind them, and where each one is implemented. It is the acceptance list for
the release that introduced the full-width inventory, the audit-trail modal,
CSP-safe filtering, the GitHub build link, explicit tenant scopes, the
cluster-local μVault, and the protocol explainer.

## Requirements

| ID | Requirement | Decision | Where |
| --- | --- | --- | --- |
| R1 | The lifecycle inventory is too narrow and forces lateral scrolling to see all columns. | Move the audit trail out of the side panel (see R2) so the inventory spans the full shell width; keep `overflow-x: auto` only as the narrow-screen fallback. | `internal/web/templates/index.html`, `identity-list.html`, `static/app.css` |
| R2 | The Audit Trail details section should open over the grid instead of squeezing the inventory. | The audit trail (and the audited ✦ use result) opens in a modal dialog over the grid: close button, Escape, and backdrop click close it; focus is restored on close. | `index.html`, `events.html`, `static/app.js`, `app.css` |
| R3 | Filters do not work — neither text search nor the status buttons. | Root cause: Alpine.js evaluates `x-*` attributes with `new Function()`, which the site CSP (`script-src 'self' https://cdn.jsdelivr.net`) correctly forbids, so every expression silently failed. Alpine was removed entirely and replaced by a small CSP-safe vanilla script (`static/app.js`): search filters rows by `data-search`, the All/Attention/Healthy buttons filter by `data-urgency`, the empty row appears when nothing matches, filters re-apply after HTMX swaps, and `/` focuses the search box. No `unsafe-eval` was added. | `static/app.js`, `index.html`, `identity-list.html` |
| R4 | The site must link the GitHub build that generated this version. | The footer of every page links the exact commit: the container build injects `BUILD_SHA` via ldflags into `internal/buildinfo`, with the toolchain's VCS stamp as the fallback for local builds. When the revision is unknown the link is omitted. | `internal/buildinfo/`, `Dockerfile`, `internal/web/server.go`, both page footers |
| R5 | The providers footer must state the Azure tenant ID, AWS account ID, and GCP project ID explicitly. | The composition root passes `config.Public.Providers` descriptors with pre-built scopes — `tenant <id>`, `account <id>`, `project <id>` — so the footer names each wired cloud scope explicitly, even before the first identity exists. These identifiers are not secrets (they ride in tokens and ARNs), but credentials never appear. | `internal/config/config.go`, `cmd/mutandae/main.go`, `internal/web/server.go` |
| R6 | A common vault where credentials persist in the cluster was never provisioned; the protocol's vault delivery should be demonstrable end to end. | Two additions. (a) **Azure Key Vault** was provisioned (`mutandae-demo-kv-7f3a`, RBAC) and granted `Key Vault Secrets Officer` to the `mutandae-eval` principal; live delivery and audited retrieval are verified. (b) **HashiCorp Vault 1.21.4** runs on the k3s cluster as the demo's **common vault**: raft storage on a Longhorn PVC (credentials survive restarts), KV v2 engine at `mutandae/`, a least-privilege `mutandae-demo` policy, an SOPS-managed unseal key with a self-healing unseal sidecar, and NetworkPolicy restricting access to the two application pods. Every provisioned or rotated credential is mirrored into it (`credential.delivered` audit events name the cluster μVault vault), `Use` falls back to it when a provider-native vault is not configured, and retirement revokes the cluster copy. Paths are isolated per environment: `mutandae/demo/live/…` and `mutandae/demo/preview/…`. The GCP Secret Manager and (pending operator grant) AWS Secrets Manager deliveries complete the native-vault picture; their grants are documented in `docs/live-demo.md`. | `internal/provider/hashicorpvault.go`, `internal/lifecycle/lifecycle.go`, `cmd/mutandae/main.go`, `belacca-gitops` `clusters/belacca-production/mutandae/{vault.yaml,vault-secret.yaml,network-policy.yaml}` |
| R7 | The protocol is testable but the site never explains what it is, why it was invented, and what value it brings. | A "What is the μTandae Protocol?" section on the dashboard: what (a small, versioned, provider-neutral lifecycle/rotation protocol over JSON, media type `application/vnd.mutandae.v1+json`), why (machine identities are fragmented across provider APIs; ownership, expiry, renewal health are invisible; renewal is manual and risky), the value (portability across Azure/AWS/GCP adapters, audited evidence for every change, renewal health at a glance, honest open-core boundary), and a Try-it block with the discovery/configuration/list endpoints plus links to the spec and JSON Schema. | `index.html`, `static/app.css` |

## Non-goals

- No new runtime dependencies: the client script is hand-written vanilla JS;
  HashiCorp Vault is spoken to over its plain HTTP KV v2 API with the standard
  library, matching the AWS/GCP/Azure vault adapters.
- No change to the μTandae Protocol v1 wire contract: the cluster vault mirror
  reuses `VaultReference`, and its audit entries are ordinary
  `credential.delivered` / `credential.used` / `credential.revoked` events
  marked `vault_kind: cluster-mutandae-vault`.
- The cluster vault holds only zero-permission demo identity credentials under
  the `mutandae/demo/…` prefix. It is not a customer secret store, and the
  control plane still never persists secret values outside the configured
  vaults.

## Verification

- `go test -race ./...`, `go vet ./...`, and `gofmt` clean across the repo.
- Web-layer tests assert the modal, the protocol section, the build link, the
  explicit `tenant `/`account `/`project ` footer scopes (including the
  descriptor-overrides-identity authority order), and the absence of Alpine
  attributes.
- Lifecycle tests cover the mirror semantics: native + cluster delivery,
  cluster fallback on `Use`, best-effort revocation on retirement, and the
  "mirror failure never fails the operation" rule.
- Provider tests cover the HashiCorp Vault KV v2 client against a fake server
  (token header, sanitized paths, versioning, sealed-state errors, redaction)
  and the GCP Secret-Manager-safe derivation of service-account-email names.
- A gated integration test exercises the real cluster μVault end to end:
  store, read, versioned rotation, pinned read, revocation.
- Live rollout checks on `https://mutandae.com`:
  - `/api/v1/configuration` advertises `vault:azure-entra`, `vault:aws-iam`,
    `vault:gcp-iam`, and `vault:cluster`.
  - The footer names `tenant ee37cc75-…`, `account 572030963802`,
    `project mutandae-demo`, the cluster μVault line, and the build commit.
  - Provisioning an Azure identity delivered to **both** the real Azure Key
    Vault (`mutandae-mutandae-demo-…`) and the cluster μVault
    (`mutandae/demo/live/…`); `Use` retrieved the credential from the Key
    Vault under audit; rotation wrote version 2 to both; retirement revoked
    both copies — each step an audited event.
  - Provisioning a GCP identity delivered to the real GCP Secret Manager
    (service-account-email name sanitized to a valid secret id) and the
    cluster μVault.
  - AWS native delivery currently surfaces the honest attention event: the
    `secretsmanager:PutSecretValue` grant documented above still needs the
    operator's admin session; the cluster μVault copy works.
- Playwright checks on the live dashboard: search and status filters act on
  the rows, the audit modal opens over the grid and closes via button,
  Escape, and backdrop, the table renders without horizontal overflow at
  1280px and 1440px, and the browser console shows zero errors.
