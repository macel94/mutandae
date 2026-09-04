# Contributing to Mutandae

Thank you for helping improve Mutandae (pronounced **moo-TAHN-dye**). The
project is an open-core machine-identity lifecycle control plane. Contributions
should preserve the provider-neutral protocol, honest trust boundaries, and
small operational surface.

## Development setup

Requirements:

- Go 1.24 or newer;
- Git; and
- a local HTTP client such as `curl` for API smoke checks.

Clone the repository, then run the credential-less demo:

```sh
go test ./...
go run ./cmd/mutandae
# open http://localhost:8080
```

The default local composition uses the in-memory store and simulated providers.
`REDIS_URL` is optional; set it to a reachable Redis URL when testing the
Redis-backed snapshot and pub/sub repository. If it is set and Redis cannot be
parsed or reached, startup fails rather than silently changing persistence
modes.

Real provider credentials are not needed for normal development. Real-cloud
evaluation is opt-in, destructive to the disposable identities in its scope,
and documented in [docs/integration-testing.md](docs/integration-testing.md):

```sh
MUTANDAE_EVAL=1 go test -tags=realclouds -count=1 ./internal/eval/...
```

Never use production credentials for tests. Follow
[docs/security-model.md](docs/security-model.md) and the real-mode warning in
[README.md](README.md) before wiring any cloud account, tenant, or project.

## Architecture and house rules

- Keep `cmd/` as the composition root. Wire concrete infrastructure there;
  domain packages and HTTP handlers must not construct providers, databases, or
  clients themselves.
- Keep lifecycle and protocol logic provider-neutral. Provider mechanics belong
  behind the adapter boundary.
- Keep the project dependency-light. Cloud clients and provider integrations
  use the Go standard library; do not add cloud SDKs or framework dependencies
  without a documented reason and maintainer agreement. The existing Redis
  client is an explicit infrastructure exception.
- Inject clocks, loggers, persistence/services, provider adapters, and outbound
  clients when they affect behavior or test determinism. Use a small interface
  at a real boundary, or a function type for one operation.
- Constructors validate required dependencies and return errors. Do not panic
  for runtime configuration, request input, or provider failures.
- Avoid package-level mutable state and hidden singletons. Make ownership and
  resource lifetimes explicit.
- Pass `context.Context` through operations that may block or call an external
  system, honor cancellation, and use bounded server shutdown.
- Do not put credentials or secret values in source, fixtures, documentation,
  screenshots, logs, events, snapshots, receipts, or ordinary HTML output.

The public simulator must model meaningful lifecycle and audit outcomes without
pretending to be a production cloud or embedding provider credentials.

## Tests and verification

Every behavior change needs focused tests at the smallest useful boundary:

- domain transition and decision tests for lifecycle behavior;
- `httptest` handler tests for HTTP and HTML behavior;
- adapter contract or conformance tests for provider boundaries; and
- integration tests only when they are explicitly environment-gated and use
  disposable, least-privileged credentials.

Before opening a pull request, run the checks relevant to the change. For Go
changes, the normal full set is:

```sh
gofmt -w <changed-go-files>
go test ./...
go test -race ./...
go vet ./...
git diff --check
```

Documentation and legal changes must still pass `git diff --check` and the
repository's documentation/link checks. Do not add real credentials, live
account identifiers, or customer data while testing documentation.

## Pull requests

1. Create a focused branch from the current `main`.
2. Explain the user-visible behavior, security/trust-boundary implications,
   and test commands in the pull request description.
3. Keep unrelated formatting and generated deployment changes out of the PR.
4. Update the relevant protocol, provider, security, or operational documents
   when behavior changes.
5. Run the required checks and include their results.
6. Sign every commit using the Developer Certificate of Origin:

   ```sh
   git commit -s
   ```

   The resulting `Signed-off-by: Name <email>` line certifies that you have
   the right to submit the work under the project terms. Pull requests without
   the required DCO sign-off may be held until corrected.

Maintainers may request changes, additional tests, or a narrower scope. Do not
stage or publish generated deployment changes as a substitute for source
changes.

## Questions and security reports

For ordinary questions, design discussion, and contribution help, open a
GitHub issue or discussion with enough context for another contributor to
reproduce the question. Do not put sensitive security details or credentials
there. Use the private process in [SECURITY.md](SECURITY.md) for vulnerabilities.

Relevant project references include:

- [docs/product-objectives.md](docs/product-objectives.md)
- [docs/open-core-boundary.md](docs/open-core-boundary.md)
- [docs/providers.md](docs/providers.md)
- [docs/security-model.md](docs/security-model.md)
- [docs/integration-testing.md](docs/integration-testing.md)
