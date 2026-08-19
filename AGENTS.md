# Mutandae project instructions

## Go architecture and dependency injection

- Keep `cmd/` as the composition root. Wire concrete implementations there; do not construct infrastructure inside domain or HTTP handlers.
- Prefer small interfaces defined by the consuming package. Add an interface only at a real boundary or when it makes a collaborator replaceable in tests; do not create broad interfaces for every type.
- Inject side effects that affect behavior or test determinism, including clocks, loggers, persistence/services, provider adapters, and outbound clients. Prefer a function type for a single operation such as `Clock`; use a small interface for a collaborator with multiple operations.
- Keep domain logic in provider-neutral packages and keep provider-specific execution behind an adapter boundary. The frontend must depend on control-plane contracts, never cloud SDK details.
- Constructors should validate required dependencies and return errors rather than panic. Panics are reserved for truly impossible programmer errors, not runtime configuration or request paths.
- Avoid package-level mutable state and hidden singletons. Make ownership and lifecycle of resources explicit.
- Pass `context.Context` through operations that may block or call external systems. Honor cancellation and use bounded shutdown in servers.

## Testability and verification

- Every behavior change needs focused tests at the smallest useful layer: domain transition/decision tests, handler tests with `httptest`, and adapter contract/conformance tests where applicable.
- Use fixed/injected time in tests; do not assert behavior based on wall-clock time or sleeps.
- Prefer fakes/spies at package boundaries over tests coupled to concrete infrastructure. Keep integration tests for wiring and real serialization/rendering behavior.
- Run `gofmt`, `go test ./...`, `go test -race ./...`, `go vet ./...`, and `git diff --check` before considering Go work complete.
- Keep tests deterministic, parallel-safe, and independent. Do not share mutable fixtures across tests.
- Test success, invalid transitions, not-found/terminal states, cancellation or timeout behavior, and concurrent access where relevant.

## Project-specific implementation choices

- The public demo is intentionally dependency-light: Go standard library, `html/template`, HTMX, Alpine.js, and an in-memory simulator.
- Keep the simulator honest: it must model meaningful lifecycle and audit outcomes without containing production provider credentials or pretending to be a production Azure adapter.
- Treat Mutandae as Latin: use the Classical Latin approximation **moo-TAHN-dye** (`mūtandae`), with the final `ae` as the Latin “ai” diphthong. Do not anglicize the name.
- Container and K3s manifests must run as an unprivileged user, expose health probes, avoid embedding secrets, and document any placeholder image or cluster-specific configuration.
