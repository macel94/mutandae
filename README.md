# Mutandae

**Mutandae** is an open-core machine identity lifecycle platform for governing, renewing, rotating, and retiring non-human cloud identities.

The visual and protocol mark is **μTandae**. Technical identifiers use the ASCII spelling `mutandae`.

**Pronunciation:** use the Classical Latin reading **moo-TAHN-dye** (`mūtandae`), with the final `ae` pronounced as the Latin diphthong *ai*. Do not anglicize the final `ae` to an English “day” sound.

> **Mutandae — Govern what must change.**

## Status

This repository contains the runnable public layer: the versioned **μTandae Protocol** (`pkg/protocol`), a small control-plane backend that speaks it, a simulated Azure/Entra ID provider adapter, and the open-source frontend — wired as one Azure-first demo.

## Product thesis

Machine identities are fragmented across cloud providers, ownership is often unclear, and credential renewal is frequently manual, inconsistent, and operationally risky.

Mutandae provides a workflow-centric control plane that standardizes the lifecycle and governance of non-human identities while remaining provider-aware at the implementation layer.

Mutandae is not intended to replace:

- Cloud IAM systems
- Vault or general-purpose secret managers
- PAM platforms
- A complete enterprise IAM suite

It provides the lifecycle governance and renewal orchestration layer above those systems.

## Core product objectives

1. Create one understandable lifecycle model for machine identities across Azure/Entra ID, AWS IAM, and GCP IAM.
2. Make ownership, governance, expiry, renewal health, and retirement visible and actionable.
3. Define a portable public lifecycle and rotation protocol.
4. Prove the model through one excellent Azure-first vertical slice.
5. Keep provider-specific production renewal and secure managed execution commercially meaningful.
6. Minimize plaintext exposure and avoid becoming a generic long-term credential warehouse.

See [Product Objectives](docs/product-objectives.md).

## MVP direction

The MVP is intentionally narrow:

- Azure-first
- One real end-to-end provider integration
- One complete machine-identity lifecycle flow
- One ownership and governance story
- One renewal/rotation story
- One credible open-core architecture

The public project will contain the frontend, shared protocol, public abstractions, and a very small control-plane shell. Provider-specific production renewal engines, secure managed execution, and advanced integrations remain private/commercial.

See [MVP Objectives](docs/mvp-objectives.md) and [Open-Core Boundary](docs/open-core-boundary.md).

## Naming decision

| Use | Decision |
|---|---|
| Commercial/product name | **Mutandae** |
| Visual wordmark | **μTandae** |
| Protocol name | **μTandae Protocol** / **Mutandae Protocol** |
| Repository, package, API, and URL spelling | `mutandae` |
| Chosen pronunciation | **moo-TAHN-dye** (Classical Latin `mūtandae`) |

The name is inspired by the Latin root *mutare*, associated with changing or altering, and by the product idea of things that are due for controlled change. For pronunciation, treat the word as Latin: *mūtandae* is approximately **moo-TAHN-dye**; keep the final *ae* as the Latin “ai” diphthong. The visual identity may draw on the Greek letter μ and the Japanese concept 丹田 (*tanden*), but `μTandae` is a creative brand treatment—not a literal Greek/Japanese translation.

Name availability has been provisionally screened across public web results, domains, GitHub, npm, PyPI, and UK company records. This is not legal trademark clearance. A professional trademark search is required before commercial launch.

See [Brand Decisions](docs/brand-decisions.md).

## Repository map

```text
.
├── .github/
│   ├── dependabot.yml         # Go, Docker, and Actions updates
│   └── workflows/ci.yml       # Test, build, and GHCR publish pipeline
├── cmd/mutandae/              # Go application entrypoint (composition root)
├── pkg/protocol/              # μTandae Protocol v1: schemas, envelopes, validation
├── internal/provider/         # Simulated azure-entra provider adapter
├── internal/lifecycle/        # Control-plane domain store + adapter boundary
├── internal/web/              # HTTP handlers, templates, CSS, protocol JSON API
├── deploy/k3s/                # Later-stage Kubernetes deployment baseline
├── Dockerfile
├── go.mod
└── docs/
    ├── protocol.md            # μTandae Protocol v1 specification
    ├── azure-demo.md          # Azure-first demo run guide
    ├── hosted-demo-gitops.md   # Hosted preview/live Redis + GitOps runbook
    ├── brand-decisions.md
    ├── implementation.md
    ├── mvp-objectives.md
    ├── open-core-boundary.md
    └── product-objectives.md
```

## Run the demo (Azure-first)

You can test the hosted user experience at:

- **Live:** <https://mutandae.com>
- **Preview/sandbox:** <https://preview.mutandae.com>
- **Configuration:** append `/configuration` to either host

The demo starts from Azure: a simulated Entra ID tenant exposes its application
registrations, the control plane discovers and governs them over the μTandae
Protocol, and the frontend renders the lifecycle. It is synthetic and does not
accept real Azure credentials.

For local development:

```sh
go run ./cmd/mutandae
# open http://localhost:8080
# protocol discovery: curl http://localhost:8080/api/v1/
# safe runtime configuration: curl http://localhost:8080/api/v1/configuration
```

Set `REDIS_URL` to use the temporary Redis-backed snapshot/pub-sub store; leave
it unset for process-local development. Set `MUTANDAE_ENVIRONMENT=preview` or
`live` to isolate Redis key prefixes.

See [docs/azure-demo.md](docs/azure-demo.md) for the walkthrough and every
protocol endpoint. See [docs/hosted-demo-gitops.md](docs/hosted-demo-gitops.md)
for the replicable hosted deployment. See [docs/protocol.md](docs/protocol.md)
for the protocol specification and the machine-readable
[`pkg/protocol/schema/mutandae.v1.json`](pkg/protocol/schema/mutandae.v1.json)
JSON Schema. See [Implementation Choices](docs/implementation.md) for the
architecture, tests, container image, GHCR publishing, and future K3s path.

The repository is currently private. The published runtime image is intended to be public in GHCR so the native K3s cluster can pull it without a registry credential. Native DNS, TLS, routing, and Flux deployment configuration lives in the private `belacca-gitops` repository.

## Working principles

- Prefer lifecycle clarity over raw provider-state replication.
- Treat ownership as a first-class product object.
- Keep conceptual abstractions provider-neutral and implementations provider-aware.
- Make renewal state and audit correlation explicit.
- Be honest about trust boundaries and operator visibility.
- Build the narrowest vertical slice that proves the thesis.
- Keep the public layer real and useful without exposing the managed execution moat.

## Planned next implementation steps

1. ~~Define the public lifecycle/rotation protocol.~~ → **done**: `pkg/protocol` v1.
2. ~~Define the canonical domain model and state transitions.~~ → **done** in `pkg/protocol` + `internal/lifecycle`.
3. ~~Build a minimal runnable control-plane shell with a local/simulated provider adapter.~~ → **done**: Azure-first demo.
4. ~~Build the open-source frontend around lifecycle and governance workflows.~~ → **done** (HTMX dashboard + protocol API).
5. Add the private Azure renewal boundary without publishing provider-specific production logic.
6. Validate the complete Azure-first vertical slice against the MVP success criteria.

See [MVP Objectives](docs/mvp-objectives.md) for the milestones and success criteria.
