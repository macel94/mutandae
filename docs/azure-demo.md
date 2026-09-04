# Azure-first demo

The Mutandae demo starts from a simulated Azure / Entra ID tenant. Its application registrations are discovered by the `azure-entra` provider adapter and adopted into governance by the Mutandae control plane over the μTandae Protocol. The browser dashboard and the versioned JSON API then expose the same governed identities, lifecycle transitions, and audit evidence.

The demo now also seeds simulated AWS IAM users and GCP IAM service accounts behind the same adapter boundary, so the default inventory is multi-cloud. This document is the Azure-focused walkthrough; see [multi-cloud-demo.md](multi-cloud-demo.md) for the combined inventory and cross-provider walkthrough.

This walkthrough deliberately follows the credential-less local default: the
Azure portion is a simulator and the default inventory also seeds simulated AWS
IAM and GCP IAM identities. The binary also ships real Azure/Entra, AWS IAM, and
GCP IAM adapters; the composition root selects a real adapter when its
credential environment is present. Read [providers.md](providers.md) and
[integration-testing.md](integration-testing.md) before wiring real
credentials. The separate Configuration-page workflow is documented in
[azure-integration.md](azure-integration.md) and uses an expiring in-memory
session. The hosted preview/live deployments use a temporary Redis snapshot
backend with environment-scoped keys and pub/sub invalidation; local runs
remain in-memory unless `REDIS_URL` is set. Use `/configuration` to inspect the
safe runtime contract.

## Run it

Requirements: Go 1.24 or newer.

```sh
go run ./cmd/mutandae
```

Open the dashboard at <http://localhost:8080>.

The command in `cmd/mutandae` is the composition root. It uses these environment variables:

| Variable | Default | Effect |
|---|---|---|
| `PORT` | `8080` | HTTP listening port. Values outside `1`–`65535` are ignored and fall back to `8080`. |
| `MUTANDAE_TENANT` | `8c0e6c1a-mutandae-4c3b-9f2d-000000000000-demo` | Synthetic tenant label reported by the simulated adapter. |
| `MUTANDAE_ENVIRONMENT` | `preview` | Redis key-prefix environment and safe UI label. |
| `REDIS_URL` | unset | Optional Redis URL. When set, startup fails closed if Redis cannot be parsed or pinged; when unset, local state is in-memory. |

The hosted deployment keeps `MUTANDAE_ENVIRONMENT=preview` and
`MUTANDAE_ENVIRONMENT=live` separate while using one Redis server. The Redis
URL and password are GitOps-managed Secret data and never appear in the public
configuration page.

For example:

```sh
PORT=9090 MUTANDAE_TENANT=my-demo-tenant go run ./cmd/mutandae
# open http://localhost:9090
```

The simulator fixes its provider clock when the process starts. Therefore, the seeded expiry offsets below are relative to startup, while API timestamps are emitted as RFC3339 values at startup or when an operation runs.

## Architecture flow

```text
simulated Azure / Entra ID tenant
        application registrations
                    │
                    ▼
internal/provider
  provider.Simulator (kind: azure-entra)
  Discover / Rotate / Retire
                    │  lifecycle.Adapter
                    ▼
internal/lifecycle
  lifecycle.Store
  NewStore -> Discover -> adopt
  List / Get / Events / Runs
  Register / Rotate / Retire
                    │  LifecycleService
                    ▼
internal/web
  HTML dashboard + HTMX fragments
  μTandae Protocol v1 JSON API
```

### Package boundaries

- **`internal/provider`** contains the provider-aware simulator. It models a fixed Azure / Entra ID tenant and application registrations, but returns provider-neutral `protocol.MachineIdentity` values. Its adapter boundary is `lifecycle.Adapter`, with the provider-specific operations:
  - `Discover(ctx)` returns the current application registrations;
  - `Rotate(ctx, identity)` changes the simulated credential and returns provider evidence (`key_id`, `fingerprint`, and the new provider expiry);
  - `Retire(ctx, identity)` disables the simulated registration.
- **`internal/lifecycle`** owns the provider-neutral control plane. `lifecycle.NewStore` calls `Adapter.Discover`, assigns each discovered identity a governance ID from its name, adopts it as active, and records `identity.discovered` followed by `identity.registered`. The store operations are `List`, `Get`, `Events`, `Runs`, `Register`, `Rotate`, and `Retire`. `Rotate` and `Retire` call the adapter, while the store remains authoritative for lifecycle state, governance expiry, rotation-run status, and audit records.
- **`internal/web`** consumes the store through the small `LifecycleService` interface. It renders the dashboard and HTMX partials and exposes the same store operations through the `/api/v1` protocol JSON API. `pkg/protocol` supplies the shared models and envelopes; the API emits `application/vnd.mutandae.v1+json; charset=utf-8`.

The initial adoption is real control-plane work: the store does not invent a disconnected sample list. It starts by asking the simulated tenant to `Discover`, then adopts each returned application registration into governance.

## Seeded identities

The Azure simulator seeds four application registrations (4 of the 10 identities in the multi-cloud inventory). `Expiry offset` is relative to the simulator's startup time. Every seeded registration has a 90-day renewal policy (`P90D`). The dashboard derives `expiring` when expiry is within 30 days and `overdue` when expiry has passed; `health` is the protocol health field.

| Identity | Environment | Expiry offset | Health | Policy days |
|---|---|---:|---|---:|
| `payments-api` | `production` | +5 days | `attention` | 90 |
| `data-pipeline` | `staging` | +18 days | `healthy` | 90 |
| `inventory-sync` | `production` | +75 days | `healthy` | 90 |
| `legacy-reporting` | `production` | −3 days | `attention` | 90 |

The control-plane list is ordered by expiry ascending, so the initial API list starts with `legacy-reporting`, then `payments-api`, `data-pipeline`, and `inventory-sync`. A successful rotation recalculates the governed expiry from the current time plus the identity's policy period and can change that order. A successful rotation also changes the simulated identity's health to `healthy`.

## Configuration page

`GET /configuration` is a public, read-only explanation of the deployment
contract. `GET /api/v1/configuration` returns the same safe information as a
versioned protocol envelope. The runtime configuration endpoints do not accept
mutation requests. The page's separate optional integration panel accepts a
real tenant ID, client ID, and temporary client password only over a CSRF-
protected POST; see [azure-integration.md](azure-integration.md) for the
permission, vault, session, and cleanup rules. The integration never puts
credentials into Redis or lifecycle snapshots.

## HTML dashboard routes

The root page is a server-rendered dashboard. The action routes return HTML rather than protocol JSON, and are intended for the HTMX controls in the page.

| Method | Path | Behavior |
|---|---|---|
| `GET` | `/` | Full dashboard: inventory, lifecycle summary, and audit-trail panel. |
| `GET` | `/partials/identities` | Re-renders the `#identity-list` inventory fragment. The dashboard Refresh button uses this route. |
| `GET` | `/identities/{id}/events` | Renders the selected identity's audit trail, newest event first. Returns `404` for an unknown identity. |
| `POST` | `/identities/{id}/rotate` | Performs a synchronous simulated rotation and returns the refreshed identity-list fragment. The server supplies the dashboard reason and operator. |
| `POST` | `/identities/{id}/retire` | Performs an explicitly confirmed retirement and returns the refreshed identity-list fragment. The browser displays a confirmation prompt before posting. |

The HTML retirement action sets `confirm: true` internally. For a direct protocol retirement request, confirmation must be present in the JSON body as described below.

## Health probes

Both probes return HTTP `200` with the plain-text body `ok\n`:

```sh
curl -i http://localhost:8080/livez
curl -i http://localhost:8080/readyz
```

## μTandae Protocol v1 API

The API is rooted at `/api/v1/`. Responses use the versioned media type emitted by the server. `curl` itself is sufficient. Runtime-generated timestamps are shown as `<RFC3339 timestamp>`. Response snippets are compact: list and identity objects may omit unrelated fields, but every field name shown is emitted by the protocol.

### `GET /api/v1/` — discovery

Discover the API version, media type, and available resources:

```sh
curl -s http://localhost:8080/api/v1/
```

Compact response shape:

```json
{
  "api_version": "v1",
  "service": "mutandae-control-plane",
  "media_type": "application/vnd.mutandae.v1+json",
  "resources": [
    {"rel":"identities","method":"GET","href":"/api/v1/identities","envelope":"list"},
    {"rel":"identity","method":"GET","href":"/api/v1/identities/{id}","envelope":"inspect"},
    {"rel":"register","method":"POST","href":"/api/v1/identities","envelope":"register"},
    {"rel":"rotate","method":"POST","href":"/api/v1/identities/{id}/rotations","envelope":"rotate"},
    {"rel":"retire","method":"POST","href":"/api/v1/identities/{id}/retire","envelope":"retire"}
  ]
}
```

### `GET /api/v1/identities` — list

List all identities currently governed by the in-memory store:

```sh
curl -s http://localhost:8080/api/v1/identities
```

The initial response has `total: 4` for this Azure-focused walkthrough; the default multi-cloud demo returns `total: 10` (see [multi-cloud-demo.md](multi-cloud-demo.md)). The identity objects use the protocol's actual nested `provider`, `ownership`, `policy`, and `credential` shapes:

```json
{
  "api_version": "v1",
  "total": 4,
  "identities": [
    {"id":"legacy-reporting","name":"legacy-reporting","environment":"production","state":"active","health":"attention","expires_at":"<startup RFC3339 timestamp - 3 days>"},
    {"id":"payments-api","name":"payments-api","environment":"production","state":"active","health":"attention","expires_at":"<startup RFC3339 timestamp + 5 days>"},
    {"id":"data-pipeline","name":"data-pipeline","environment":"staging","state":"active","health":"healthy","expires_at":"<startup RFC3339 timestamp + 18 days>"},
    {"id":"inventory-sync","name":"inventory-sync","environment":"production","state":"active","health":"healthy","expires_at":"<startup RFC3339 timestamp + 75 days>"}
  ]
}
```

The default tenant ID above is replaced by the value of `MUTANDAE_TENANT` when that variable is set. The other seeded provider IDs end in `0001` (`payments-api`), `0002` (`data-pipeline`), and `0003` (`inventory-sync`).

### `GET /api/v1/identities/{id}` — inspect

Inspect one governed identity. The control-plane ID for a seeded identity is its name:

```sh
curl -s http://localhost:8080/api/v1/identities/payments-api
```

Response envelope:

```json
{
  "api_version": "v1",
  "identity": {
    "id": "payments-api",
    "name": "payments-api",
    "display_name": "payments-api",
    "environment": "production",
    "provider": {
      "provider": "azure-entra",
      "provider_id": "00000000-0000-0000-0000-000000000001",
      "tenant_id": "8c0e6c1a-mutandae-4c3b-9f2d-000000000000-demo",
      "object_id": "00000000-0000-0000-0000-000000000001",
      "region": "westeurope"
    },
    "ownership": {"team":"Payments Platform","service":"Payment authorization","purpose":"Authorizes payment processing workloads","criticality":"critical","contacts":["payments-api@mutandae.example"]},
    "policy": {"renewal_period":"P90D","approval_required":false},
    "credential": {"kind":"client_secret","location":"keyvault://mutandae-vault/secrets/payments-api","fingerprint":"sha256:00000000000000000000000000000001","key_id":"payments-api-initial-secret","delivery":"keyvault-ref"},
    "state": "active",
    "health": "attention",
    "expires_at": "<startup RFC3339 timestamp + 5 days>",
    "last_rotated_at": "<startup RFC3339 timestamp - 85 days>",
    "created_at": "<startup RFC3339 timestamp>",
    "updated_at": "<startup RFC3339 timestamp>"
  }
}
```

An unknown ID returns HTTP `404` with the canonical failure envelope:

```json
{"api_version":"v1","error":{"code":"not_found","message":"identity not found"}}
```

### `POST /api/v1/identities` — register

Register a new protocol identity directly into control-plane governance. This route is useful for demonstrating the protocol registration envelope; unlike startup adoption, it does not call the provider adapter. The request needs a name, provider binding, ownership team, and parseable renewal policy.

```sh
curl -s -X POST http://localhost:8080/api/v1/identities \
  -H 'Content-Type: application/json' \
  -d '{
    "id":"demo-registration",
    "name":"demo-registration",
    "display_name":"Demo registration",
    "environment":"staging",
    "provider":{
      "provider":"azure-entra",
      "provider_id":"demo-registration-object",
      "tenant_id":"8c0e6c1a-mutandae-4c3b-9f2d-000000000000-demo",
      "object_id":"demo-registration-object",
      "region":"westeurope"
    },
    "ownership":{
      "team":"Platform Engineering",
      "service":"Demo worker",
      "purpose":"Demonstrates protocol registration",
      "criticality":"low"
    },
    "policy":{"renewal_period":"P90D","approval_required":false},
    "requested_by":"demo-operator"
  }'
```

The server returns HTTP `201`. It computes `expires_at` as the registration time plus the requested renewal period; the request's optional `expires_at` is not used by the current store implementation.

Compact response shape:

```json
{
  "api_version": "v1",
  "identity": {
    "id": "demo-registration",
    "name": "demo-registration",
    "display_name": "Demo registration",
    "environment": "staging",
    "provider": {"provider":"azure-entra","provider_id":"demo-registration-object","tenant_id":"8c0e6c1a-mutandae-4c3b-9f2d-000000000000-demo","object_id":"demo-registration-object","region":"westeurope"},
    "ownership": {"team":"Platform Engineering","service":"Demo worker","purpose":"Demonstrates protocol registration","criticality":"low"},
    "policy": {"renewal_period":"P90D","approval_required":false},
    "credential": {"kind":"","location":""},
    "state": "active",
    "health": "healthy",
    "expires_at": "<request RFC3339 timestamp + 90 days>",
    "created_at": "<request RFC3339 timestamp>",
    "updated_at": "<request RFC3339 timestamp>"
  },
  "events": [
    {"id":"evt-<n>","identity_id":"demo-registration","type":"identity.registered","summary":"Registered demo-registration into governance","actor":"demo-operator","outcome":"success","at":"<request RFC3339 timestamp>"}
  ]
}
```

Credential material is not generated by this registration operation. The zero-value `credential` object shown above is the shape produced when no credential reference is supplied.

### `POST /api/v1/identities/{id}/rotations` — rotate

Start and complete a synchronous simulated rotation. The current handler takes the identity from the path and uses `demo-operator` unless the `X-Mutandae-Operator` header is provided; it uses the fixed reason `protocol api`.

```sh
curl -s -X POST http://localhost:8080/api/v1/identities/payments-api/rotations \
  -H 'X-Mutandae-Operator: demo-operator'
```

The response includes the post-rotation identity, one correlated `rotation` run, and the identity's event history. On a fresh process, the run ID is `run-001`; subsequent runs increment it.

```json
{
  "api_version": "v1",
  "identity": {
    "id": "payments-api",
    "name": "payments-api",
    "state": "active",
    "health": "healthy",
    "expires_at": "<rotation RFC3339 timestamp + 90 days>",
    "last_rotated_at": "<rotation RFC3339 timestamp>",
    "credential": {
      "kind": "client_secret",
      "location": "keyvault://mutandae-vault/secrets/payments-api",
      "fingerprint": "sha256:00000000000000000000000000000066",
      "key_id": "payments-api-credential-2",
      "delivery": "keyvault-ref"
    }
  },
  "rotation": {
    "id": "run-001",
    "identity_id": "payments-api",
    "status": "succeeded",
    "requested_by": "demo-operator",
    "requested_at": "<rotation RFC3339 timestamp>",
    "started_at": "<rotation RFC3339 timestamp>",
    "finished_at": "<rotation RFC3339 timestamp>",
    "outcome": "success",
    "evidence": {
      "kind": "client_secret",
      "location": "keyvault://mutandae-vault/secrets/payments-api",
      "fingerprint": "sha256:00000000000000000000000000000066",
      "key_id": "payments-api-credential-2",
      "delivery": "keyvault-ref"
    }
  },
  "events": [
    {"id":"<event id>","identity_id":"payments-api","type":"identity.discovered","summary":"Discovered payments-api in the azure-entra tenant","actor":"discovery","outcome":"success","at":"<startup RFC3339 timestamp>","details":{"provider_id":"00000000-0000-0000-0000-000000000001"}},
    {"id":"<event id>","identity_id":"payments-api","type":"identity.registered","summary":"Registered payments-api into governance","actor":"control-plane","outcome":"success","at":"<startup RFC3339 timestamp>"},
    {"id":"<event id>","identity_id":"payments-api","type":"rotation.requested","summary":"Rotation requested by demo-operator","actor":"demo-operator","outcome":"in_progress","at":"<rotation RFC3339 timestamp>","run_id":"run-001","details":{"reason":"protocol api"}},
    {"id":"<event id>","identity_id":"payments-api","type":"rotation.started","summary":"Rotation dispatched to azure-entra","actor":"control-plane","outcome":"in_progress","at":"<rotation RFC3339 timestamp>","run_id":"run-001"},
    {"id":"<event id>","identity_id":"payments-api","type":"rotation.completed","summary":"New credential verified against provider state","actor":"provider-adapter","outcome":"success","at":"<rotation RFC3339 timestamp>","run_id":"run-001","details":{"key_id":"payments-api-credential-2","fingerprint":"sha256:00000000000000000000000000000066"}}
  ]
}
```

The simulated sequence increments its credential sequence from `payments-api-initial-secret` to `payments-api-credential-2`. The exact event IDs and timestamps depend on what has already happened in the running process. The store records `rotation.requested`, `rotation.started`, and `rotation.completed`; the dashboard's event view displays the newest events first.

### `POST /api/v1/identities/{id}/retire` — retire

Retirement is an explicit lifecycle transition and **must include** `{"confirm":true}` in the JSON request body. The path supplies the identity ID. The optional `reason` is retained in the retirement event, and `requested_by` defaults to `operator` unless the header is supplied.

```sh
curl -s -X POST http://localhost:8080/api/v1/identities/legacy-reporting/retire \
  -H 'Content-Type: application/json' \
  -H 'X-Mutandae-Operator: demo-operator' \
  -d '{"confirm":true,"reason":"replaced by the finance reporting workload"}'
```

Response shape:

```json
{
  "api_version": "v1",
  "identity": {
    "id": "legacy-reporting",
    "name": "legacy-reporting",
    "state": "retired",
    "health": "attention",
    "provider": {"provider":"azure-entra","provider_id":"00000000-0000-0000-0000-000000000004","tenant_id":"8c0e6c1a-mutandae-4c3b-9f2d-000000000000-demo","object_id":"00000000-0000-0000-0000-000000000004","region":"westeurope"}
  },
  "events": [
    {"id":"<event id>","identity_id":"legacy-reporting","type":"identity.discovered","summary":"Discovered legacy-reporting in the azure-entra tenant","actor":"discovery","outcome":"success","at":"<startup RFC3339 timestamp>","details":{"provider_id":"00000000-0000-0000-0000-000000000004"}},
    {"id":"<event id>","identity_id":"legacy-reporting","type":"identity.registered","summary":"Registered legacy-reporting into governance","actor":"control-plane","outcome":"success","at":"<startup RFC3339 timestamp>"},
    {"id":"<event id>","identity_id":"legacy-reporting","type":"identity.retired","summary":"Retired legacy-reporting (replaced by the finance reporting workload)","actor":"demo-operator","outcome":"success","at":"<retirement RFC3339 timestamp>"}
  ]
}
```

The simulator disables the corresponding Entra ID registration. Disabled registrations are not returned by a future provider `Discover` call, and the governed identity remains visible in the current store as `state: "retired"` with `health: "attention"`.

Omitting confirmation returns HTTP `409` with the protocol error envelope:

```json
{"api_version":"v1","error":{"code":"conflict","message":"retirement requires explicit confirmation"}}
```

## Walkthrough

### 1. Observe discovery and adoption

1. Start the server and open <http://localhost:8080>.
2. The dashboard shows the ten governed identities across the simulated Azure, AWS, and GCP adapters; the four seeded Azure application registrations are part of that inventory.
3. Select an identity's audit-trail button. Chronologically, its initial events are:
   - `identity.discovered`, emitted by the `discovery` actor with the provider ID in `details`;
   - `identity.registered`, emitted by the `control-plane` actor as the registration is adopted into governance.

   The dashboard displays events newest first, so `identity.registered` appears above `identity.discovered`.
4. The inventory makes the seeded states visible: `legacy-reporting` is overdue, `payments-api` is expiring soon and needs attention, `data-pipeline` is also expiring soon but healthy, and `inventory-sync` is healthy.

### 2. Rotate `payments-api` and inspect correlation and evidence

1. Click **Rotate** for `payments-api`, or call the protocol endpoint:

   ```sh
   curl -s -X POST http://localhost:8080/api/v1/identities/payments-api/rotations
   ```

2. Inspect `payments-api` again or select its audit trail.
3. Confirm that the identity returns to `state: "active"`, its `health` is `"healthy"`, and its governed expiry is approximately 90 days after the rotation time.
4. In the JSON response, inspect the correlated `rotation` object. Its terminal status is `"succeeded"`, its `identity_id` is `"payments-api"`, and its `evidence` contains the provider-observed `key_id` and `fingerprint`.
5. In the event history, find `rotation.requested`, `rotation.started`, and `rotation.completed`. Each rotation event carries the same `run_id` as the `RotationRun`; the completed event also repeats `key_id` and `fingerprint` in `details`.

### 3. Retire an identity with explicit confirmation

1. Use the dashboard's **Retire** action and accept its explicit confirmation prompt, or call the API with the required JSON confirmation:

   ```sh
   curl -s -X POST http://localhost:8080/api/v1/identities/legacy-reporting/retire \
     -H 'Content-Type: application/json' \
     -d '{"confirm":true,"reason":"demo decommission"}'
   ```

2. The response shows `state: "retired"` and `health: "attention"`.
3. Open the identity's audit trail and verify the `identity.retired` event. The simulator has disabled the provider registration, so the retired registration will not be rediscovered by the adapter.
