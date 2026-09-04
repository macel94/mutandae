# Mutandae

**Mutandae** is an open-core machine identity lifecycle control plane for
governing, renewing, rotating, and retiring non-human cloud identities.

The visual and protocol mark is **μTandae**. Technical identifiers use the ASCII
spelling `mutandae`.

## Name and pronunciation

| Use | Convention |
| --- | --- |
| Product name | **Mutandae** |
| Visual and protocol mark | **μTandae** |
| Technical spelling | `mutandae` |
| Pronunciation | **moo-TAHN-dye** (`mūtandae`), with final `ae` as the Latin “ai” diphthong |

Do not anglicize the final `ae` to an English “day” sound.

> **Mutandae — Govern what must change.**

## What ships in this release

This repository contains the runnable public layer: the versioned **μTandae
Protocol** (`pkg/protocol`), a small control-plane backend, the HTMX frontend,
and provider adapters for Azure/Entra ID, AWS IAM, and GCP IAM.

The real adapters are in-tree and use only the Go standard library for their
provider clients:

- Azure/Entra ID uses Microsoft Graph and Key Vault HTTP clients;
- AWS IAM uses the IAM Query API with SigV4 signing; and
- GCP IAM uses JWT assertion and REST calls.

The composition root wires a real adapter automatically when its credential
environment variables are present. Without real credentials, local development
and ordinary tests use the credential-less simulators. The simulator is a
useful deterministic default; it is not a claim that a cloud mutation occurred.

To run the real-cloud evaluation against disposable, least-privileged
identities, use the environment-gated harness:

```sh
MUTANDAE_EVAL=1 go test -tags=realclouds -count=1 ./internal/eval/...
```

The lifecycle protocol and control-plane abstractions are open and provider
neutral. Production operations, managed execution, and advanced integrations
may remain part of the commercial offering; see [Open-Core
Boundary](docs/open-core-boundary.md) for the intended split.

## Real mode warning

> [!WARNING]
> When real provider credentials are wired, Mutandae can make real cloud
> mutations against the configured Entra tenant, AWS account, or GCP project.
> **Rotate** creates and replaces credentials; **retire** revokes or deletes
> provider credentials or objects; and permanent **delete** removes an already-
> retired control-plane record and its audit history (it does not issue another
> provider API mutation). Treat the rotate/retire/delete workflow as
> destructive. Use disposable identities, least-privileged credentials, and a
> narrow scope allow-list. Never expose the unauthenticated HTTP port directly
> to the internet. Until the planned auth workstream (OIDC, API tokens, and
> RBAC) lands, bind to localhost or a private VPN, or put the service behind a
> trusted reverse-proxy/SSO boundary.
>
> Demo-mode adapters restrict governed names to the `mutandae-demo-*` namespace;
> evaluation identities should use the documented disposable `mutandae-eval-*`
> scope. These guards complement, but do not replace, cloud IAM policy. Read
> [docs/security-model.md](docs/security-model.md) and
> [docs/integration-testing.md](docs/integration-testing.md) before connecting
> credentials.

## Product thesis

Machine identities are fragmented across cloud providers, ownership is often
unclear, and credential renewal is frequently manual, inconsistent, and
operationally risky.

Mutandae provides a workflow-centric control plane that standardizes the
lifecycle and governance of non-human identities while remaining provider-aware
at the implementation layer.

Mutandae is not intended to replace:

- cloud IAM systems;
- Vault or general-purpose secret managers;
- PAM platforms; or
- a complete enterprise IAM suite.

It provides a lifecycle governance and renewal orchestration layer above those
systems.

## Core product objectives

1. Create one understandable lifecycle model for machine identities across
   Azure/Entra ID, AWS IAM, and GCP IAM.
2. Make ownership, governance, expiry, renewal health, and retirement visible
   and actionable.
3. Define a portable public lifecycle and rotation protocol.
4. Exercise one provider-neutral control plane against simulators and real
   cloud APIs through the same adapter boundary.
5. Minimize plaintext exposure and avoid becoming a generic long-term
   credential warehouse.

See [Product Objectives](docs/product-objectives.md).

## Current identity coverage

The current release covers these credential-backed identity classes:

- Entra application password credentials;
- AWS IAM user access keys; and
- GCP service-account user-managed keys.

It does not yet claim support for managed identities, certificate or federated
credentials, IAM roles or instance profiles, SSO identities, SPIFFE/X.509, or
GitHub/GitLab tokens. The [public roadmap](docs/roadmap.md) keeps those gaps
explicit.

## Run the demo

You can inspect the hosted experience at:

- **Live:** <https://mutandae.com>
- **Preview/sandbox:** <https://preview.mutandae.com>
- **Configuration:** append `/configuration` to either host

The hosted environments can use real, namespace-scoped provider adapters. Treat
those sites as demonstrations, not as a safe place for customer credentials.

For local development:

```sh
go run ./cmd/mutandae
# open http://localhost:8080
# protocol discovery: curl http://localhost:8080/api/v1/
# safe runtime configuration: curl http://localhost:8080/api/v1/configuration
```

Set `REDIS_URL` to use the temporary Redis-backed snapshot/pub-sub store; leave
it unset for process-local development. Set `MUTANDAE_ENVIRONMENT=preview` or
`live` to isolate Redis key prefixes. The simulator labels are configurable
with `MUTANDAE_TENANT`, `MUTANDAE_AWS_ACCOUNT`, `MUTANDAE_AWS_REGION`,
`MUTANDAE_GCP_PROJECT`, and `MUTANDAE_GCP_REGION` (see `.env.example`).

When real credentials are present, the same command wires the corresponding
real adapter automatically. The optional native vault settings are
`AZURE_KEY_VAULT_URL` and `AZURE_KEY_VAULT_PREFIX` for Azure Key Vault, plus
`VAULT_ADDR`/`VAULT_TOKEN` for the optional cluster μVault mirror. Provider
native vault delivery is scoped by the adapter and cloud permissions; it is not
a substitute for authentication on the HTTP surface.

See [docs/multi-cloud-demo.md](docs/multi-cloud-demo.md) for the local
walkthrough and protocol endpoints. Per-provider details are in
[docs/azure-demo.md](docs/azure-demo.md),
[docs/aws-integration.md](docs/aws-integration.md), and
[docs/gcp-integration.md](docs/gcp-integration.md). See
[docs/live-demo.md](docs/live-demo.md) for the hosted real-tenant safety model,
vault prerequisites, and cleanup procedure. See
[docs/integration-testing.md](docs/integration-testing.md) for the credentials,
permissions, and real-cloud evaluation checklist.

## Repository map

```text
.
├── .github/                  # Repository automation and dependency updates
├── cmd/mutandae/             # Go application entrypoint and composition root
├── pkg/protocol/             # μTandae Protocol v1 schemas and validation
├── internal/provider/        # Simulators plus real Graph/SigV4/JWT adapters
├── internal/lifecycle/       # Provider-neutral store and adapter boundary
├── internal/web/             # HTTP handlers, templates, CSS, and API
├── deploy/k3s/               # Kubernetes deployment baseline
├── Dockerfile
├── go.mod
└── docs/
    ├── protocol.md          # μTandae Protocol v1 specification
    ├── providers.md         # Provider adapters and identity coverage
    ├── security-model.md    # Trust boundaries and credential handling
    ├── roadmap.md           # Public coverage and planned work
    ├── ci.md                # CI and release checks (parallel workstream)
    ├── azure-demo.md        # Synthetic Azure/Entra walkthrough
    ├── multi-cloud-demo.md  # Local multi-cloud walkthrough
    ├── azure-integration.md # Optional Azure/Entra integration contract
    ├── aws-integration.md   # AWS IAM integration contract
    ├── gcp-integration.md   # GCP IAM integration contract
    ├── integration-testing.md # Real-cloud evaluation requirements
    ├── live-demo.md         # Hosted demo safety and vault runbook
    ├── implementation.md    # Architecture and implementation choices
    ├── open-core-boundary.md
    └── product-objectives.md
```

## Working principles

- Prefer lifecycle clarity over raw provider-state replication.
- Treat ownership as a first-class product object.
- Keep conceptual abstractions provider-neutral and implementations
  provider-aware.
- Make renewal state and audit correlation explicit.
- Be honest about trust boundaries and operator visibility.
- Keep provider mutations behind narrow, testable adapter boundaries.
- Minimize plaintext exposure and never put credentials in audit data.

## Further reading

- [Security model](docs/security-model.md)
- [Public roadmap](docs/roadmap.md)
- [Provider reference](docs/providers.md)
- [Integration-testing contract](docs/integration-testing.md)
- [Open-core boundary](docs/open-core-boundary.md)
- [Product objectives](docs/product-objectives.md)
- [CI and release checks](docs/ci.md)

## License

Mutandae code is available under the [Apache License 2.0](LICENSE). The
Mutandae and μTandae names and wordmark are trademarks of the project owner;
see [NOTICE](NOTICE). The code license does not grant trademark rights.

## Security

See [SECURITY.md](SECURITY.md) for private vulnerability reporting and
supported versions. Before using real credentials, read the
[security model](docs/security-model.md) and follow the real-mode warning above.
