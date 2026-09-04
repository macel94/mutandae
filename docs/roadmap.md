# Public roadmap

This roadmap describes the published Mutandae release, not a promise of a
particular date or commercial packaging. **Shipped in this release** means the
behavior exists in this repository at the publication point. In the identity
coverage table, `shipped` is the target marker for coverage already present;
`next`, `near`, and `far` mark the relative target for gaps. Parallel work that
has not landed in this source tree is marked **planned** even when it is being
worked on elsewhere.

## Identity-class coverage

The control plane and real adapters are intentionally narrower than the full
identity surface of each provider.

| Provider / identity class | Status in this release | Target marker |
| --- | --- | --- |
| Entra application password credentials | **Covered today** — real Graph adapter discovers, creates, rotates, and retires demo-namespaced applications and their password credentials. | `shipped` |
| AWS IAM user access keys | **Covered today** — real SigV4 adapter discovers IAM users and rotates/retires their access keys. | `shipped` |
| GCP service-account user-managed keys | **Covered today** — real JWT/REST adapter discovers service accounts with downloadable user-managed keys and rotates/retires them. | `shipped` |
| AWS IAM roles | **Not covered yet** — role lifecycle and role credential assumptions are not modeled. | `near` |
| AWS IAM instance profiles | **Not covered yet** — instance-profile attachment and workload delivery are not modeled. | `near` |
| AWS IAM Identity Center / SSO | **Not covered yet** — SSO assignments and ephemeral sessions are outside the current adapter contract. | `far` |
| Entra managed identities | **Not covered yet** — system- and user-assigned managed identity lifecycle is not implemented. | `next` |
| Entra certificate credentials | **Not covered yet** — certificate issuance, rollover, and trust distribution are not implemented. | `near` |
| Entra federated credentials | **Not covered yet** — workload identity federation credential definitions are not implemented. | `near` |
| SPIFFE/SPIRE and X.509 workload identities | **Not covered yet** — no SPIFFE/SPIRE or general X.509 adapter ships. | `far` |
| GitHub tokens | **Not covered yet** — GitHub App, fine-grained PAT, and token rotation are not modeled. | `far` |
| GitLab tokens | **Not covered yet** — GitLab project/group/personal token lifecycle is not modeled. | `far` |

“Covered” means adapter-level lifecycle behavior for the listed credential
class, not universal provider discovery or support for every policy and delivery
mode. Covered rows use `shipped` because they are present in this release;
gaps use the relative `next`, `near`, or `far` target markers. See
[providers.md](providers.md) for the adapter contract.

## Shipped in this release

- μTandae Protocol v1 schemas, envelopes, validation, and discovery.
- Provider-neutral lifecycle state transitions, rotation runs, audit events,
  explicit retirement confirmation, and permanent deletion of retired
  control-plane records.
- HTMX dashboard and protocol JSON API for inventory, ownership, expiry,
  rotation, retirement, audit, and vault-backed use.
- Credential-less Azure/Entra, AWS IAM, and GCP IAM simulators for local
  development and deterministic tests.
- Standard-library real adapters for Azure/Entra Graph, AWS IAM SigV4, and GCP
  IAM JWT/REST, selected automatically when the corresponding credentials are
  present.
- Demo-only namespace guards, per-client-IP rate limiting, and explicit
  confirmation for destructive lifecycle operations.
- Optional delivery to Azure Key Vault, AWS Secrets Manager, GCP Secret
  Manager, and a cluster-local HashiCorp Vault KV v2 mirror, with references
  rather than secret values in control-plane records.
- Environment-gated real-cloud evaluation harness and secret-redaction tests.
- Apache-2.0 licensing, security reporting guidance, and the published trust
  model in [security-model.md](security-model.md).

## Planned work

The following are not shipped capabilities in this release:

| Workstream | Status | Why it matters |
| --- | --- | --- |
| Scheduled auto-renewal worker | **Planned** | Execute renewal policy without requiring a synchronous operator request, with bounded retries and failure visibility. |
| Durable audit sinks | **Planned** | Add an append-oriented, durable audit destination beyond optional Redis snapshots and pub/sub invalidation. |
| OIDC SSO, API tokens, and RBAC | **Planned; auth workstream in progress** | Authenticate callers and authorize operator actions before exposing a shared deployment. |
| Multi-account and multi-tenant configuration | **Planned** | Govern more than one AWS account, GCP project, or Entra tenant with explicit per-scope credentials and policy. |
| Third-party adapter conformance suite | **Planned** | Give external adapter authors executable contract tests for discovery, rotation, retirement, evidence, and redaction. |
| Broader identity classes | **Planned by target marker above** | Extend coverage without implying that provider object types are interchangeable. |

The roadmap does not change the current security posture. Until the auth mode
ships, follow the private-network or VPN/reverse-proxy guidance in
[security-model.md](security-model.md), and do not use this release as an
internet-facing authenticated control plane.
