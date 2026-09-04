#!/usr/bin/env bash
# Run the issue #4 real-cloud protocol+UI conformance harness.
#
# Usage:
#   MUTANDAE_EVAL=1 scripts/eval-realclouds.sh [aws|gcp|azure]
#
# Credentials come from the environment:
#   AWS_ACCOUNT_ID AWS_REGION AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY [AWS_SESSION_TOKEN]
#   GCP_PROJECT_ID GCP_REGION GCP_SERVICE_ACCOUNT_KEY_JSON (or GCP_SERVICE_ACCOUNT_KEY_FILE)
#   AZURE_TENANT_ID AZURE_CLIENT_ID AZURE_CLIENT_SECRET
#   MUTANDAE_EVAL_PREFIX (default mutandae-eval) — only these identities are rotated/retired
#
# The harness NEVER mutates identities outside the eval prefix and skips any
# cloud whose credentials are absent.
set -euo pipefail

usage() {
	cat <<'USAGE'
Usage: scripts/eval-realclouds.sh [aws|gcp|azure|--help]

Runs the disposable real-cloud conformance evaluator. Set the documented
cloud credentials first; absent clouds are skipped by the Go harness.
The default evaluator mutates only identities under MUTANDAE_EVAL_PREFIX
(default mutandae-eval), then rotates and retires them.
USAGE
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
	usage
	exit 0
fi
if [[ $# -gt 1 ]]; then
	printf 'error: expected at most one cloud selector\n' >&2
	usage >&2
	exit 2
fi

cat >&2 <<'WARNING'
DANGER: the real-cloud evaluator creates/rotates/retires disposable cloud
identities. Run only with narrowly scoped evaluation principals and a
mutandae-eval* namespace; clean up credentials and principals afterward.
WARNING

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$script_dir/.." || exit 1

export MUTANDAE_EVAL="${MUTANDAE_EVAL:-1}"
select="${1:-}"
go_args=(-tags=realclouds -count=1 -v)
case "$select" in
	aws|gcp) go_args+=(-run TestRealCloud) ;;
	azure) go_args+=(-run TestAzureReal) ;;
	"") ;;
	*) echo "unknown cloud: $select (use aws|gcp|azure)" >&2; exit 2 ;;
esac

go test "${go_args[@]}" ./internal/eval/...
