// Package eval contains the evaluator-provided integration harness that runs
// the μTandae Protocol + browser UI conformance checklist (docs/integration-testing.md,
// issue #4) against real provider APIs.
//
// It is guarded by the build tag `realclouds` and by environment variables so
// it is never executed by the default `go test ./...` or CI: each provider
// sub-test skips when its live credentials are absent, and mutations
// (rotate/retire) are restricted to identities whose provider_id matches the
// configured eval prefix (MUTANDAE_EVAL_PREFIX, default `mutandae-eval`) so a
// stray real identity in the account can never be touched accidentally.
package eval
