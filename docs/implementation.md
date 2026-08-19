# Demo implementation

## Native production delivery record

The complete native-production delivery, troubleshooting history, attestation
compatibility findings, and final verification are documented in
[`docs/native-production-delivery.md`](native-production-delivery.md).

This repository now contains a runnable Azure-first vertical slice: a versioned μTandae Protocol in `pkg/protocol`, a simulated Azure/Entra ID provider adapter in `internal/provider`, a control-plane store in `internal/lifecycle`, and the open-source frontend plus a protocol JSON API in `internal/web`.

## Product name and pronunciation

Use the Classical Latin reading **moo-TAHN-dye** (`mūtandae`). The final `ae` is the Latin diphthong, approximated by “ai” or “eye”; do not anglicize it to an English “day” sound. The technical spelling remains ASCII `mutandae`.

## Choices

### Backend: Go standard library

The backend uses Go 1.24, `net/http`, `html/template`, `embed`, and the standard JSON encoder. This is intentionally dependency-free for the fastest edit-run-test cycle:

- no framework conventions to learn before the domain model is stable;
- server-rendered HTML keeps the public control-plane contract visible;
- `html/template` escapes interpolated values by default;
- the same binary serves HTML, fragments, CSS, health checks, and a small JSON inventory endpoint;
- the in-memory simulator makes the demo deterministic and keeps provider credentials out of the public layer;
- the web package defines a small consumer-side `LifecycleService` interface instead of depending on the concrete store;
- `Clock` and `Logger` are injected as dependencies, with concrete wiring kept in `cmd/mutandae` as the composition root;
- constructors validate required dependencies and tests use fixed clocks plus fake services, avoiding sleeps and wall-clock assertions.

Templ is a good future option if the template surface grows or component-level type safety becomes valuable. It is not required for this small first slice, and avoiding a code-generation tool keeps the initial container and contributor workflow simpler.

### Frontend: HTMX + Alpine.js

- **HTMX 2.0.10** handles server interactions: refreshing the inventory, loading an identity's audit trail, and posting a rotation request. The server returns HTML fragments rather than making the frontend duplicate domain rendering logic.
- **Alpine.js 3.16.2** handles browser-local state: inventory search, status filters, and the responsive navigation toggle.
- Both are pinned CDN assets, so there is no Node or frontend build step. A production deployment can vendor these assets or serve them from an approved internal asset origin.
- CSS is a single embedded static asset with no framework dependency. The visual language uses restrained technical typography, a paper-like surface, and cinnabar as a renewal/change accent rather than a generic lock or shield metaphor.

### Domain and provider boundary

### Protocol (public contract)

`pkg/protocol` is the versioned, provider-neutral **μTandae Protocol** consumed by
cloud adapters, the control plane, and the frontend. It owns the object schemas
(`MachineIdentity`, `ProviderBinding`, `Ownership`, `LifecyclePolicy`,
`CredentialReference`, `LifecycleEvent`, `RotationRun`), the enumerations,
message envelopes, ISO-8601 durations, the canonical state machine, and
conformance validation. It never encodes provider mechanics or credentials. See
[docs/protocol.md](protocol.md).

### Provider adapter boundary

`internal/lifecycle` defines a small consumer-side `Adapter` interface
(`Discover`, `Rotate`, `Retire`) that speaks protocol types. `internal/provider`
ships the public demo's **simulated azure-entra adapter**: it presents a tenant,
application object ids, and credential evidence (key id, fingerprint, location),
without any Azure SDK, credentials, or service endpoints. Production renewals
implement the same boundary privately.

### Control-plane store

`internal/lifecycle.Store` is the protocol-native control plane. The demo
*begins from the cloud*: at startup the store calls `adapter.Discover`, adopts
each non-conformant-checked identity into governance, and audits
`identity.discovered` + `identity.registered`. `Rotate` moves a governed
identity through the canonical state machine (`active → renewing → active`),
dispatches the adapter, applies the governed expiry from policy, records a
correlated `RotationRun` plus evidence and `rotation.completed`; on adapter
failure it returns to active with attention health and a `rotation.failed` run
so a retry stays possible. `Retire` requires an explicit confirmation, asks the
adapter to disable the registration, and audits `identity.retired`.

The canonical transitions are:

- `registered → active`;
- `active → renewing → active`;
- `active → retired`; `renewing → retired` (aborted renewal).

The `cmd/mutandae` package is the composition root: it wires the simulated
Azure adapter into the store, plus clock, logger, HTTP server, and a bounded
shutdown policy. Tests inject fakes and fixed time.

The seeded identities cover healthy, expiring-soon, and overdue states so the
evaluator experience is representative without pretending the simulator is a
real Azure tenant.

## Run locally

Requirements: Go 1.24 or newer. No Node, templ, database, or external service
is needed.

```sh
go test ./...
go run ./cmd/mutandae
# open http://localhost:8080
```

Useful endpoints:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Full dashboard |
| `GET` | `/partials/identities` | HTMX inventory fragment |
| `GET` | `/identities/{id}/events` | HTMX audit-trail fragment |
| `POST` | `/identities/{id}/rotate` | Rotation + refreshed inventory |
| `POST` | `/identities/{id}/retire` | Retire (explicit confirm) + refreshed inventory |
| `GET` | `/api/v1/` | Protocol discovery index |
| `GET` | `/api/v1/identities` | Protocol list envelope |
| `GET` | `/api/v1/identities/{id}` | Protocol inspect envelope |
| `POST` | `/api/v1/identities` | Protocol register envelope |
| `POST` | `/api/v1/identities/{id}/rotations` | Protocol rotate envelope |
| `POST` | `/api/v1/identities/{id}/retire` | Protocol retire envelope (requires `{"confirm":true}`) |
| `GET` | `/livez` | Liveness probe |
| `GET` | `/readyz` | Readiness probe |

All `/api/v1` responses use the versioned content type
`application/vnd.mutandae.v1+json` and conform to the protocol.

## Container

Build and run with a local OCI-compatible runtime:

```sh
docker build -t mutandae:demo .
docker run --rm -p 8080:8080 mutandae:demo
```

The image is a static Linux binary running as an unprivileged user. The demo has no writable application state, so the Kubernetes baseline uses a read-only root filesystem. The private repository's GitHub Actions workflow builds and publishes `ghcr.io/macel94/mutandae` on trusted pushes to `main`. It also publishes keyless Sigstore/Cosign provenance, a CycloneDX SBOM, and a native-production vulnerability decision so the cluster's Kyverno admission policies can verify the image. This works while the source repository remains private because the attestations are stored with the public GHCR image rather than in GitHub's private-repository attestation storage.

The image receives an immutable source-commit tag and `latest`; the generated deployment commit records the exact tag and digest in `deploy/k3s/kustomization.yaml`. Pull requests run tests and a non-publishing container build. The workflow uses the ephemeral `GITHUB_TOKEN` with job-scoped `packages: write` and `id-token: write` permissions; no long-lived registry or signing secret is required. The runtime image is intended to be public in GHCR while the source repository remains private. Docker base image and GitHub Actions updates are managed weekly by Dependabot.

## K3s later

`deploy/k3s/` is a deliberately small Deployment, Service, Namespace, and Kustomize application baseline. It includes startup/readiness/liveness probes and a restrictive container security context, but it does not assume an ingress controller, registry credentials, domain, TLS issuer, persistence layer, or GitOps system. Native production adds those cluster-level resources in the private `belacca-gitops` repository.

Before applying it to the cluster:

1. Wait for the GitHub Actions publish job to push an image and generate the digest-pinning deployment commit.
2. Use the generated `sha-...` tag and digest from `deploy/k3s/kustomization.yaml`.
3. Let the private `belacca-gitops` repository own the cluster-specific Ingress, TLS, Flux source, and admission policy configuration.
4. Replace the in-memory store with persistence before treating the deployment as durable.
5. Add the private provider adapter and secret-delivery boundary separately; do not put credentials in this demo manifest.

```sh
kubectl kustomize deploy/k3s
# Native production is applied by Flux from the private belacca-gitops repository.
```

The manifest is a deployment starting point, not a production security or availability claim.
