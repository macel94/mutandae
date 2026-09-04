#!/usr/bin/env bash
# Provision the least-privilege Google Cloud governor used by Mutandae.
#
# DANGER: This script changes a Google Cloud project, creates a service
# account, grants a custom role, and writes a private JSON key. Run it only
# against a disposable evaluation project. The key is not printed; protect the
# reported file path and delete the key after the evaluation.
set -euo pipefail
# Keep private key material out of logs even when the caller enabled xtrace.
set +x
umask 077

usage() {
	cat <<'USAGE'
Usage: scripts/gcp-governor.sh [--help]

Creates or updates custom project role mutandaeGovernor, creates or reuses the
mutandae-governor service account, binds the role with a mutandae-* resource
condition, and writes a JSON service-account key.

Inputs:
  GCP_PROJECT_ID             Required (or the active gcloud project).
  GCP_SERVICE_ACCOUNT_KEY_FILE  Optional output path; default is under
                               ~/.config/mutandae with mode 0600.

The key material is never echoed. The printed GCP_SERVICE_ACCOUNT_KEY_FILE
path is the only credential reference emitted by this script.
USAGE
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
	usage
	exit 0
fi
if [[ $# -ne 0 ]]; then
	printf 'error: unexpected argument: %s\n\n' "$1" >&2
	usage >&2
	exit 2
fi

command -v gcloud >/dev/null 2>&1 || {
	printf 'error: gcloud CLI is required\n' >&2
	exit 127
}

cat >&2 <<'WARNING'
DANGER: this changes the selected Google Cloud project and writes a private
service-account JSON key. Confirm the project before continuing. The governor
role is intended for disposable mutandae-* evaluation resources only; revoke
the key and remove the role binding after the test.
WARNING

readonly role_id='mutandaeGovernor'
readonly service_account_id='mutandae-governor'
project_id="${GCP_PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
[[ -n "$project_id" && "$project_id" != '(unset)' ]] || {
	printf 'error: set GCP_PROJECT_ID or configure an active gcloud project\n' >&2
	exit 1
}
[[ "$project_id" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || {
	printf 'error: GCP_PROJECT_ID has an invalid format\n' >&2
	exit 1
}

project_number="$(gcloud projects describe "$project_id" --format='value(projectNumber)')"
[[ "$project_number" =~ ^[0-9]+$ ]] || {
	printf 'error: gcloud did not return a numeric project number\n' >&2
	exit 1
}
service_account_email="${service_account_id}@${project_id}.iam.gserviceaccount.com"
role_name="projects/${project_id}/roles/${role_id}"

# These are the exact key-management and namespace-limited Secret Manager
# permissions required by the evaluator. Service-account listing cannot be
# narrowed by name in all IAM APIs, so the binding condition is defense in depth
# for resource-bearing operations.
readonly permissions='iam.serviceAccounts.list,iam.serviceAccounts.get,iam.serviceAccountKeys.list,iam.serviceAccountKeys.create,iam.serviceAccountKeys.delete,iam.serviceAccountKeys.disable,secretmanager.secrets.create,secretmanager.versions.add,secretmanager.versions.access'
if gcloud iam roles describe "$role_id" --project "$project_id" >/dev/null 2>&1; then
	gcloud iam roles update "$role_id" \
		--project "$project_id" \
		--title='Mutandae governor' \
		--description='Mutandae evaluation service-account key and namespaced secret lifecycle' \
		--permissions="$permissions" \
		--stage=GA \
		--quiet >/dev/null
else
	gcloud iam roles create "$role_id" \
		--project "$project_id" \
		--title='Mutandae governor' \
		--description='Mutandae evaluation service-account key and namespaced secret lifecycle' \
		--permissions="$permissions" \
		--stage=GA \
		--quiet >/dev/null
fi

if ! gcloud iam service-accounts describe "$service_account_email" --project "$project_id" >/dev/null 2>&1; then
	gcloud iam service-accounts create "$service_account_id" \
		--project "$project_id" \
		--display-name='Mutandae governor' \
		--quiet >/dev/null
fi

# Service-account resources use the project ID; Secret Manager resources use
# the project number. The project-level clause keeps list discovery available,
# while key/get operations and secret access stay in the mutandae-* namespace.
iam_condition="expression=resource.name == \"projects/${project_id}\" || resource.name.startsWith(\"projects/${project_id}/serviceAccounts/mutandae-\") || resource.name.startsWith(\"projects/${project_number}/secrets/mutandae-\"),title=Mutandae namespace,description=Only project discovery plus mutandae-prefixed service accounts and secrets"
gcloud projects add-iam-policy-binding "$project_id" \
	--member="serviceAccount:${service_account_email}" \
	--role="$role_name" \
	--condition="$iam_condition" \
	--quiet >/dev/null

key_file="${GCP_SERVICE_ACCOUNT_KEY_FILE:-${HOME}/.config/mutandae/mutandae-governor-$(date -u +%Y%m%dT%H%M%SZ).json}"
if [[ -e "$key_file" ]]; then
	printf 'error: refusing to overwrite existing key file: %s\n' "$key_file" >&2
	exit 1
fi
mkdir -p -- "$(dirname -- "$key_file")"
chmod 700 -- "$(dirname -- "$key_file")"
gcloud iam service-accounts keys create "$key_file" \
	--iam-account "$service_account_email" \
	--project "$project_id" \
	--quiet >/dev/null
chmod 600 -- "$key_file"

printf '\nThe private key was written once with mode 0600; do not copy its contents into logs.\n'
printf 'export GCP_PROJECT_ID=%q\n' "$project_id"
printf 'export GCP_SERVICE_ACCOUNT_KEY_FILE=%q\n' "$key_file"
printf '\nCleanup after the evaluation (replace <KEY_ID> with the user-managed key id):\n'
printf 'gcloud iam service-accounts keys list --iam-account %q --managed-by=user\n' "$service_account_email"
printf 'gcloud iam service-accounts keys delete <KEY_ID> --iam-account %q --quiet\n' "$service_account_email"
printf 'gcloud projects remove-iam-policy-binding %q --member=%q --role=%q --condition=%q --quiet\n' "$project_id" "serviceAccount:${service_account_email}" "$role_name" "$iam_condition"
printf 'gcloud iam service-accounts delete %q --project %q --quiet\n' "$service_account_email" "$project_id"
printf 'gcloud iam roles delete %q --project %q --quiet\n' "$role_id" "$project_id"
printf 'rm -f -- %q\n' "$key_file"
