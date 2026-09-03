# Mutandae

**Mutandae** is an open-core machine identity lifecycle platform for governing, renewing, rotating, and retiring non-human cloud identities.

The visual and protocol mark is **μTandae**. Technical identifiers use the ASCII spelling `mutandae`.

**Pronunciation:** use the Classical Latin reading **moo-TAHN-dye** (`mūtandae`), with the final `ae` pronounced as the Latin diphthong *ai*. Do not anglicize the final `ae` to an English “day” sound.

> **Mutandae — Govern what must change.**

## Status

This repository contains the runnable public layer: the versioned **μTandae Protocol** (`pkg/protocol`), a small control-plane backend that speaks it, three simulated provider adapters (Azure/Entra ID, AWS IAM, GCP IAM), and the open-source frontend — wired as one multi-cloud demo.

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
4. Prove the model through one excellent Azure-first vertical slice, now extended to AWS IAM and GCP IAM with simulated adapters behind the same adapter boundary.
5. Keep provider-specific production renewal and secure managed execution commercially meaningful.
6. Minimize plaintext exposure and avoid becoming a generic long-term credential warehouse.

See [Product Objectives](docs/product-objectives.md).

## MVP direction

The MVP is intentionally narrow:

- Azure-first, extended with AWS IAM and GCP IAM simulated adapters
- One real end-to-end provider integration (Azure interactive extension)
- One complete machine-identity lifecycle flow
- One ownership and governance story
- One renewal/rotation story
- One credible open-core architecture

The public demo adds a live **New identity** flow on top: pick an identity type (Azure / Entra ID, AWS IAM, or GCP IAM) and the control plane creates a real zero-permission identity in that tenant, delivers the credential into that cloud's native vault (Azure Key Vault, AWS Secrets Manager, or GCP Secret Manager) and mirrors it into the cluster-local μVault (HashiCorp Vault on the demo k3s cluster), and makes the secret retrievable on demand — every use, renewal, and revocation is an audited lifecycle event. See the [live demo](docs/live-demo.md) and [multi-cloud demo](docs/multi-cloud-demo.md) documents.

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
├── internal/provider/         # Multi-cloud simulated adapters + optional real Azure client
├── internal/lifecycle/        # Control-plane domain store + adapter boundary
├── internal/web/              # HTTP handlers, templates, CSS, protocol JSON API
├── deploy/k3s/                # Later-stage Kubernetes deployment baseline
├── Dockerfile
├── go.mod
└── docs/
    ├── protocol.md            # μTandae Protocol v1 specification
    ├── providers.md           # Provider adapters and the protocol (Azure/AWS/GCP)
    ├── azure-demo.md          # Synthetic Azure/Entra demo run guide
    ├── multi-cloud-demo.md    # Multi-cloud demo run guide (Azure + AWS + GCP)
    ├── azure-integration.md    # Optional real-tenant + Key Vault runbook
    ├── aws-integration.md      # AWS IAM simulator + real-world integration contract
    ├── gcp-integration.md      # GCP IAM simulator + real-world integration contract
    ├── integration-testing.md  # Credentials/permissions needed for real cloud evaluation
    ├── hosted-demo-gitops.md   # Hosted preview/live Redis + μVault + GitOps runbook
    ├── demo-requirements-2026-09.md # 2026-09 demo upgrade requirements and decisions
    ├── brand-decisions.md
    ├── implementation.md
    ├── mvp-objectives.md
    ├── open-core-boundary.md
    └── product-objectives.md
```

## Run the demo (multi-cloud)

You can test the hosted user experience at:

- **Live:** <https://mutandae.com>
- **Preview/sandbox:** <https://preview.mutandae.com>
- **Configuration:** append `/configuration` to either host

The demo starts from three simulated clouds: an Entra ID tenant
(azure-entra), an AWS IAM account (aws-iam), and a Google Cloud project
(gcp-iam). Their adapters are composited by `internal/provider.MultiProvider`;
the control plane discovers and governs the combined inventory over the μ
Tandae Protocol, and the frontend renders the lifecycle with per-provider
labels (Azure/Entra ID, AWS IAM, GCP IAM). The Configuration page also offers
an optional, ten-minute real-Azure path using exactly the Graph
`Application.ReadWrite.OwnedBy` permission. Read
[docs/azure-integration.md](docs/azure-integration.md) first; after a real-tenant
trial, invalidate the temporary client credential and remove its consent.

For local development:

```sh
go run ./cmd/mutandae
# open http://localhost:8080
# protocol discovery: curl http://localhost:8080/api/v1/
# safe runtime configuration: curl http://localhost:8080/api/v1/configuration
```

Set `REDIS_URL` to use the temporary Redis-backed snapshot/pub-sub store; leave
it unset for process-local development. Set `MUTANDAE_ENVIRONMENT=preview` or
`live` to isolate Redis key prefixes. The simulated provider labels are
configurable with `MUTANDAE_TENANT`, `MUTANDAE_AWS_ACCOUNT`,
`MUTANDAE_AWS_REGION`, `MUTANDAE_GCP_PROJECT`, and `MUTANDAE_GCP_REGION` (see
`.env.example`).

See [docs/multi-cloud-demo.md](docs/multi-cloud-demo.md) for the synthetic
walkthrough and protocol endpoints, with the per-provider details in
[docs/azure-demo.md](docs/azure-demo.md), [docs/aws-integration.md](docs/aws-integration.md), and [docs/gcp-integration.md](docs/gcp-integration.md). See [docs/azure-integration.md](docs/azure-integration.md)
for the optional real-tenant flow, vault prerequisites, the cluster μVault
bootstrap runbook, and cleanup procedure. See [docs/hosted-demo-gitops.md](docs/hosted-demo-gitops.md)
for the replicable hosted deployment. See [docs/protocol.md](docs/protocol.md)
for the protocol specification, [docs/providers.md](docs/providers.md) for the
provider adapter reference, and the machine-readable
[`pkg/protocol/schema/mutandae.v1.json`](pkg/protocol/schema/mutandae.v1.json)
JSON Schema. [docs/integration-testing.md](docs/integration-testing.md) lists
exactly what a caller must contribute (credentials, app IDs, secret API keys,
permissions) to evaluate the protocol and UI with real integration tests on
each cloud. See [Implementation Choices](docs/implementation.md) for the
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
5. ~~Extend the simulated demo to AWS IAM and GCP IAM behind the same adapter boundary.~~ → **done**: `internal/provider/multicloud.go` composites the three simulators; the frontend renders per-provider labels.
6. Add the private Azure renewal boundary without publishing provider-specific production logic.
7. Validate the protocol and UI against real AWS IAM and GCP IAM APIs with the evaluator-supplied credentials in [docs/integration-testing.md](docs/integration-testing.md), mirroring the existing Azure interactive extension.

See [MVP Objectives](docs/mvp-objectives.md) for the milestones and success criteria.
