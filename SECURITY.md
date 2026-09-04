# Security policy

Mutandae is an open-core machine-identity lifecycle control plane. This policy
covers the `main` branch and the latest published source snapshot.

## Supported versions

| Version | Supported |
| --- | --- |
| `main` | Yes |
| Older commits, forks, and unmaintained snapshots | No, unless the project owner explicitly says otherwise |

There is no promise of backported security fixes for unreleased or historical
snapshots. Pin a reviewed commit when deploying the project.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through a
[GitHub Security Advisory](https://github.com/macel94/mutandae/security/advisories/new),
not in a public issue, pull request, discussion, or chat message. Include:

- the affected commit, release, or deployment;
- a concise description of the impact and attack prerequisites;
- reproduction steps or a minimal proof of concept;
- whether provider credentials, plaintext credential material, Redis data,
  vault data, or the unauthenticated HTTP surface is involved; and
- any suggested mitigation, if known.

Do not include live credentials, tenant secrets, private keys, or customer data
in the report. If a test requires a credential, use a disposable value and
state what type of value the test needs.

If the advisory interface is unavailable, contact the project owner through a
private GitHub channel and ask for a security-reporting route. Do not publish
the vulnerability while waiting for a response.

## Response expectations

We aim to acknowledge a private report within three business days and to
provide an initial triage assessment within seven business days. Timing for a
fix, coordinated disclosure, or release depends on severity, exploitability,
provider impact, and the availability of a safe mitigation. These are targets,
not a guarantee of service or a promise of a particular disclosure date.

We may ask for additional reproduction details, coordinate a temporary
workaround, and credit reporters who want attribution. Please allow a
reasonable coordination period before public disclosure.

## In scope

Reports are especially valuable when they demonstrate one of the following:

- mishandling, unintended persistence, or disclosure of Azure/Entra, AWS, or
  GCP adapter credentials;
- failure to redact client secrets, AWS secret access keys, GCP private keys,
  Graph tokens, or generated secret text from events, snapshots, receipts,
  logs, or ordinary HTML/API output;
- an authorization or scope failure in the control-plane API that permits an
  unintended provider mutation or bypasses confirmation and namespace guards;
- a vulnerability in the Redis persistence/event boundary or provider-native
  and cluster μVault delivery boundary; or
- a web/API issue that exposes the unauthenticated demo surface to an
  unreasonable denial of service or enables cross-tenant/provider access.

The default HTTP surface is intentionally unauthenticated for the demo. A
report that the demo has no authentication is not by itself a vulnerability;
reports showing an unsafe deployment expectation, missing warning, bypass of
rate limits, or unintended access are in scope.

## Out of scope

- vulnerabilities in a cloud provider, GitHub, Redis, Vault, Kubernetes, or
  third-party CDN that do not arise from Mutandae's integration;
- findings that require a user to install a deliberately malicious fork or
  ignore the documented deployment and credential-scope guidance;
- rate-limit tuning requests without a security impact; and
- trademark, licensing, documentation, or product-feature requests.

## Security model

The trust boundaries, current unauthenticated-demo posture, provider blast
radius, redaction claims, and evaluation credential hygiene are documented in
[docs/security-model.md](docs/security-model.md). Read it before connecting
real cloud credentials or exposing the HTTP listener beyond a trusted network.
