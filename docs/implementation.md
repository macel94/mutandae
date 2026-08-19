# Demo implementation

This repository now contains the first runnable Mutandae vertical slice: an in-memory control-plane shell for inspecting machine identities, seeing ownership and expiry, triggering a simulated rotation, and inspecting correlated lifecycle events.

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

`internal/lifecycle` owns provider-neutral concepts and valid state transitions. The web package consumes it through a small interface so a future persistent store, remote control-plane client, or provider adapter can be substituted without changing handlers:

- `registered → active`;
- `active → renewing → active`;
- `active → retired`.

The `cmd/mutandae` package is the composition root: it constructs the simulator, clock, logger, HTTP server, and bounded shutdown policy. Tests inject fakes and fixed time.

`Store.Rotate` is explicitly a synchronous simulator. It records `rotation.started`, updates the simulated expiry and health, records `rotation.completed`, and returns to `active`. A production adapter will implement the same boundary asynchronously, handle credential material without persisting it here, verify provider state, and add retries/recovery without changing the frontend contract.

The seeded identities cover healthy, expiring-soon, and overdue states. This makes the evaluator experience useful without pretending that the simulator is an Azure tenant integration.

## Run locally

Requirements: Go 1.24 or newer. No Node, templ, database, or external service is needed.

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
| `POST` | `/identities/{id}/rotate` | Simulated rotation and refreshed inventory |
| `GET` | `/api/identities` | Small JSON inventory contract |
| `GET` | `/livez` | Liveness probe |
| `GET` | `/readyz` | Readiness probe |

## Container

Build and run with a local OCI-compatible runtime:

```sh
docker build -t mutandae:demo .
docker run --rm -p 8080:8080 mutandae:demo
```

The image is a static Linux binary running as an unprivileged user. The demo has no writable application state, so the Kubernetes baseline uses a read-only root filesystem. The private repository's GitHub Actions workflow builds and publishes `ghcr.io/macel94/mutandae` on trusted pushes to `main`. It also publishes GitHub keyless provenance, a CycloneDX SBOM, and a native-production vulnerability decision so the cluster's Kyverno admission policies can verify the image.

The image receives an immutable source-commit tag and `latest`; the generated deployment commit records the exact tag and digest in `deploy/k3s/kustomization.yaml`. Pull requests run tests and a non-publishing container build. The workflow uses the ephemeral `GITHUB_TOKEN` with job-scoped `packages: write`, `id-token: write`, and `attestations: write` permissions; no long-lived registry secret is required. The runtime image is intended to be public in GHCR while the source repository remains private. Docker base image and GitHub Actions updates are managed weekly by Dependabot.

## K3s later

`deploy/k3s/` is a deliberately small Deployment, Service, Namespace, and Kustomize application baseline. It includes startup/readiness/liveness probes and a restrictive container security context, but it does not assume an ingress controller, registry credentials, domain, TLS issuer, persistence layer, or GitOps system. Native production adds those cluster-level resources in the private `belacca-gitops` repository.

Before applying it to the cluster:

1. Wait for the GitHub Actions publish job to push an image to GHCR, or build and publish `Dockerfile` manually.
2. Replace the example image reference in the manifest with an immutable `sha-...` tag or digest from `ghcr.io/macel94/mutandae`.
3. Add the cluster-specific Ingress and TLS configuration.
4. Replace the in-memory store with persistence before treating the deployment as durable.
5. Add the private provider adapter and secret-delivery boundary separately; do not put credentials in this demo manifest.

```sh
kubectl apply -f deploy/k3s/deployment.yaml
kubectl rollout status deployment/mutandae
kubectl port-forward service/mutandae 8080:80
```

The manifest is a deployment starting point, not a production security or availability claim.
