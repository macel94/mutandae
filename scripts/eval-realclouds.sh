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
cd "$(dirname "$0")/.."

export MUTANDAE_EVAL="${MUTANDAE_EVAL:-1}"
select="${1:-}"
run_arg=""
case "$select" in
	aws) run_arg="-run TestRealCloud" ;;
	gcp) run_arg="-run TestRealCloud" ;;
	azure) run_arg="-run TestAzureReal" ;;
	"") run_arg="" ;;
	*) echo "unknown cloud: $select (use aws|gcp|azure)" >&2; exit 2 ;;
esac

go test -tags=realclouds -count=1 -v ./internal/eval/... $run_arg