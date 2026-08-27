# Multi-cloud demo

The Mutandae demo now starts from **three simulated clouds**: an Azure / Entra
ID tenant, an AWS IAM account, and a Google Cloud project. Each provider is a
separate simulated adapter under `internal/provider/`, and the composition
root (`cmd/mutandae`) fuses them behind one `MultiProvider` adapter so the
control plane governs a single combined inventory over the μTandae Protocol.
The browser dashboard and the versioned JSON API expose the same governed
identities, lifecycle transitions, and audit evidence across clouds, with
per-provider labels.

None of the simulated providers require real credentials. The optional
real-tenant workflow remains the Azure interactive extension documented in
[azure-integration.md](azure-integration.md), isolated in an expiring in-memory
session. What a caller must contribute to evaluate a real AWS IAM or GCP IAM
integration is documented in [aws-integration.md](aws-integration.md),
[gcp-integration.md](gcp-integration.md), and
[integration-testing.md](integration-testing.md).

## Run it

Requirements: Go 1.24 or newer.

```sh
go run ./cmd/mutandae
# open http://localhost:8080
```

The command in `cmd/mutandae` is the composition root. Environment variables:

| Variable | Default | Effect |
|---|---|---|
| `PORT` | `8080` | HTTP listening port. |
| `MUTANDAE_ENVIRONMENT` | `preview` | Redis key-prefix environment and safe UI label. |
| `MUTANDAE_TENANT` | `8c0e6c1a-mutandae-4c3b-9f2d-000000000000-demo` | Synthetic tenant label for the Azure/Entra adapter. |
| `MUTANDAE_AWS_ACCOUNT` | `123456789012` | Synthetic 12-digit AWS account id for the AWS IAM adapter. |
| `MUTANDAE_AWS_REGION` | `us-east-1` | Synthetic region for the AWS IAM adapter. |
| `MUTANDAE_GCP_PROJECT` | `mutandae-demo` | Synthetic Google Cloud project id for the GCP IAM adapter. |
| `MUTANDAE_GCP_REGION` | `us-central1` | Synthetic region for the GCP IAM adapter. |
| `REDIS_URL` | unset | Optional Redis URL. When set, startup fails closed if Redis cannot be parsed or pinged. |

For example:

```sh
PORT=9090 MUTANDAE_AWS_ACCOUNT=111122223333 MUTANDAE_GCP_PROJECT=my-demo go run ./cmd/mutandae
# open http://localhost:9090
```

## Architecture flow

```text
simulated Azure / Entra tenant      simulated AWS account      simulated GCP project
        application regs.               IAM users + keys          service accounts + keys
                    │                         │                          │
                    ▼                         ▼                          ▼
                    ├──────────────── internal/provider ────────────────┤
                    │   Simulator (azure-entra)  AWSSimulator (aws-iam)  │
                    │   GCPSimulator (gcp-iam)  MultiProvider (composite)│
                    └──────────────────────────┬─────────────────────────┘
                                               │ lifecycle.Adapter
                                               ▼
                                   internal/lifecycle
                                     lifecycle.Store
                                   Discover -> adopt (per provider)
                                   List / Get / Events / Runs
                                   Register / Rotate / Retire
                                               │ LifecycleService
                                               ▼
                                   internal/web
                                    HTML dashboard + HTMX fragments
                                    μTandae Protocol v1 JSON API
```

Each simulated adapter implements the same `CloudAdapter` boundary
(`Kind`/`Discover`/`Rotate`/`Retire`). `MultiProvider` fans discovery out
across the adapters, dedupes by `(provider, provider_id)`, and routes
`Rotate`/`Retire` to the adapter whose kind matches the identity's
`ProviderBinding.provider`. See [providers.md](providers.md) for the full
reference.

## Seeded inventory

The combined inventory is **10 identities**: the four Azure application
registrations, three AWS IAM users, and three GCP service accounts. Expiry
offsets are relative to the simulator's startup time. Every seeded identity has
a 90-day renewal policy (`P90D`).

### Azure / Entra ID (`azure-entra`)

| Identity | Environment | Expiry offset | Health |
|---|---|---:|---:|
| `payments-api` | `production` | +5 days | `attention` |
| `data-pipeline` | `staging` | +18 days | `healthy` |
| `inventory-sync` | `production` | +75 days | `healthy` |
| `legacy-reporting` | `production` | −3 days | `attention` |

### AWS IAM (`aws-iam`)

| Identity | Environment | Expiry offset | Health |
|---|---|---:|---:|
| `orders-deployer` | `production` | +5 days | `attention` |
| `data-exporting` | `staging` | +18 days | `healthy` |
| `metrics-publisher` | `production` | +75 days | `healthy` |

### GCP IAM (`gcp-iam`)

| Identity | Environment | Expiry offset | Health |
|---|---|---:|---:|
| `inventory-broker` | `production` | +5 days | `attention` |
| `ml-training-runtime` | `staging` | +18 days | `healthy` |
| `catalog-replication` | `production` | +75 days | `healthy` |

The control-plane list is ordered by expiry ascending across providers, so the
initial API list starts with `legacy-reporting` (overdue), then the three
+5-day identities (`payments-api`, `orders-deployer`, `inventory-broker`), and
so on. The dashboard footer lists each provider adapter with its synthetic
scope (`tenant …`, `account …`, `project …`); each inventory row shows a
provider mark (`Az`/`AW`/`GC`) and label.

## Configuration page

`GET /configuration` is a public, read-only explanation of the deployment
contract, now including the simulated AWS and GCP adapters. `GET
/api/v1/configuration` returns the same safe information as a versioned
protocol envelope. The page's optional integration panel still accepts real
Azure tenant/client credentials only over a CSRF-protected POST; see
[azure-integration.md](azure-integration.md).

## HTML dashboard routes

The root page is a server-rendered dashboard; action routes return HTML
fragments for HTMX. Unchanged from the Azure demo:

| Method | Path | Behavior |
|---|---|---|
| `GET` | `/` | Full dashboard: multi-cloud inventory, lifecycle summary, audit-trail panel. |
| `GET` | `/partials/identities` | Re-renders the `#identity-list` inventory fragment. |
| `GET` | `/identities/{id}/events` | Renders the selected identity's audit trail, newest first. |
| `POST` | `/identities/{id}/rotate` | Synchronous simulated rotation routed to the identity's provider; returns the refreshed identity-list fragment. |
| `POST` | `/identities/{id}/retire` | Explicitly confirmed retirement routed to the identity's provider; returns the refreshed identity-list fragment. |

## Health probes

```sh
curl -i http://localhost:8080/livez
curl -i http://localhost:8080/readyz
```

Both return HTTP `200` with the plain-text body `ok\n`.

## μTandae Protocol v1 API

The API is rooted at `/api/v1/` and is provider-agnostic: the same envelopes
carry Azure, AWS, and GCP identities. Discovery is unchanged:

```sh
curl -s http://localhost:8080/api/v1/
```

### `GET /api/v1/identities` — list

```sh
curl -s http://localhost:8080/api/v1/identities
```

The initial response has `total: 10` and includes identities from all three
providers, e.g.:

```json
{
  "api_version": "v1",
  "total": 10,
  "identities": [
    {"id":"legacy-reporting","name":"legacy-reporting","environment":"production","provider":{"provider":"azure-entra","account_id":"","project_id":""},"state":"active","health":"attention"},
    {"id":"payments-api","name":"payments-api","environment":"production","provider":{"provider":"azure-entra"},"state":"active","health":"attention"},
    {"id":"orders-deployer","name":"orders-deployer","environment":"production","provider":{"provider":"aws-iam","account_id":"123456789012","region":"us-east-1"},"state":"active","health":"attention"},
    {"id":"inventory-broker","name":"inventory-broker","environment":"production","provider":{"provider":"gcp-iam","project_id":"mutandae-demo","region":"us-central1"},"state":"active","health":"attention"}
  ]
}
```

Field names match the protocol; the compact shape above omits unrelated
fields. Provider-specific fields are populated per the conventions in
[protocol.md § 2.2](protocol.md).

### Rotate across providers

Rotation is routed by the provider binding, so the same call shape works for
every cloud:

```sh
# AWS IAM access key rotation
curl -s -X POST http://localhost:8080/api/v1/identities/orders-deployer/rotations \
  -H 'X-Mutandae-Operator: demo-operator'
```

The response contains the post-rotation identity (new `key_id`,
`fingerprint`, expiry) plus a correlated `rotation` run with
`rotation.requested` → `rotation.started` → `rotation.completed` events. The
AWS credential reference becomes a new access key id
(`orders-deployer-access-key-2`), while a GCP rotation produces a new
service-account key id (`<name>-service-key-N`).

### Retire across providers

Retirement requires `confirm: true`; the adapter then disables the underlying
registration (Entra app, IAM user, or service account), which disappears from
the next discovery while the governed identity stays visible as `retired`:

```sh
curl -s -X POST http://localhost:8080/api/v1/identities/metrics-publisher/retire \
  -H 'Content-Type: application/json' \
  -H 'X-Mutandae-Operator: demo-operator' \
  -d '{"confirm":true,"reason":"replaced by the new metrics agent"}'
```

## Walkthrough

1. **Observe discovery and adoption.** Start the server and open
   <http://localhost:8080>. The dashboard shows ten governed identities across
   Azure, AWS, and GCP, each with a provider mark, label, and scope in the
   footer. Select an identity's audit-trail button; its initial events are
   `identity.discovered` (with `provider_id` in `details`) followed by
   `identity.registered`.
2. **Rotate across clouds.** Click **Rotate** on `orders-deployer` (AWS) and
   `inventory-broker` (GCP), or call the protocol endpoints above. Verify the
   identity returns to `active` with `healthy` health, a ~90-day governed
   expiry, and correlated rotation events carrying the provider-observed
   `key_id` and `fingerprint`.
3. **Retire with explicit confirmation.** Use the dashboard **Retire** action
   or the API with `{"confirm":true}`. Retiring `legacy-reporting` (Azure),
   `metrics-publisher` (AWS), or `catalog-replication` (GCP) shows
   `state: "retired"`; the simulator disabled the provider-side registration,
   so it is not rediscovered while remaining visible in the store's audit
   trail.

## Provider-specific documents

- [azure-demo.md](azure-demo.md) — Azure-focused walkthrough (protocol
  envelopes, seeded Azure registrations).
- [aws-integration.md](aws-integration.md) — AWS IAM simulator and the
  real-world integration contract (credentials, least-privilege IAM actions,
  two-key rotation model).
- [gcp-integration.md](gcp-integration.md) — GCP IAM simulator and the
  real-world integration contract (project id, service-account JSON key,
  `roles/iam.serviceAccountKeyAdmin`).
- [providers.md](providers.md) — how each adapter populates
  `ProviderBinding`, the `Lifecycle.Adapter` boundary, and the generalized
  interactive extension.
- [integration-testing.md](integration-testing.md) — exactly what a caller
  must contribute to run real integration tests on each cloud.