#!/usr/bin/env bash
# Provision the least-privilege AWS IAM governor used by Mutandae.
#
# DANGER: This script changes an AWS account. Run it only with an administrator
# session in the intended account. The access-key secret is printed exactly
# once; capture it securely and delete the key and user after the evaluation.
# No secret is written to a file by this script.
set -euo pipefail
# Do not let a caller's inherited xtrace setting print credential arguments.
set +x
umask 077

usage() {
	cat <<'USAGE'
Usage: scripts/aws-governor.sh [--help]

Creates or reuses IAM user mutandae-governor, attaches the policy in
scripts/aws-governor-policy.json with <AWS_ACCOUNT_ID> substituted, and creates
one access key. The returned secret access key is one-time output.

Inputs:
  AWS_ACCOUNT_ID  Optional 12-digit account id; otherwise sts get-caller-identity.
  AWS_REGION      Optional region for AWS CLI and the printed environment block.

The policy grants only discovery, access-key lifecycle, and
secretsmanager:* for the mutandae-* namespace. The administrator running this
script, not the governor, must perform cleanup.
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

command -v aws >/dev/null 2>&1 || {
	printf 'error: aws CLI is required\n' >&2
	exit 127
}

cat >&2 <<'WARNING'
DANGER: this creates/updates an IAM user and grants it a namespace-scoped
inline policy. Confirm the AWS account before continuing. The secret access
key below is shown once and must be captured privately, then revoked.
WARNING

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly user_name='mutandae-governor'
readonly policy_name='mutandae-governor-least-privilege'
export AWS_PAGER=''

account_id="${AWS_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text)}"
[[ "$account_id" =~ ^[0-9]{12}$ ]] || {
	printf 'error: AWS_ACCOUNT_ID must be a 12-digit account id\n' >&2
	exit 1
}
region="${AWS_REGION:-us-east-1}"
[[ "$region" =~ ^[A-Za-z0-9-]+$ ]] || {
	printf 'error: AWS_REGION contains unsupported characters\n' >&2
	exit 1
}

policy_template="$script_dir/aws-governor-policy.json"
[[ -f "$policy_template" ]] || {
	printf 'error: policy template not found: %s\n' "$policy_template" >&2
	exit 1
}
policy_file="$(mktemp)"
trap 'rm -f -- "$policy_file"' EXIT
sed "s/<AWS_ACCOUNT_ID>/${account_id}/g" "$policy_template" >"$policy_file"

if ! aws iam get-user --user-name "$user_name" --output none >/dev/null 2>&1; then
	aws iam create-user --user-name "$user_name" --output none >/dev/null
fi
aws iam put-user-policy \
	--user-name "$user_name" \
	--policy-name "$policy_name" \
	--policy-document "file://$policy_file" \
	--output none >/dev/null

key_count="$(aws iam list-access-keys --user-name "$user_name" --query 'length(AccessKeyMetadata)' --output text)"
[[ "$key_count" =~ ^[0-9]+$ ]] || {
	printf 'error: could not determine existing access-key count\n' >&2
	exit 1
}
if (( key_count >= 2 )); then
	printf 'error: %s already has two access keys; delete an old governor key before rerunning\n' "$user_name" >&2
	exit 1
fi

# Keep the tab-separated AWS CLI result in memory. Never enable shell tracing.
credential_output="$(aws iam create-access-key \
	--user-name "$user_name" \
	--query 'AccessKey.[AccessKeyId,SecretAccessKey]' \
	--output text)"
IFS=$'\t' read -r access_key_id secret_access_key <<<"$credential_output"
[[ -n "${access_key_id:-}" && -n "${secret_access_key:-}" ]] || {
	printf 'error: AWS CLI did not return an access key; nothing was printed\n' >&2
	exit 1
}

printf '\nCapture this one-time credential output in a secure secret manager.\n'
printf 'export AWS_ACCOUNT_ID=%q\n' "$account_id"
printf 'export AWS_REGION=%q\n' "$region"
printf 'export AWS_ACCESS_KEY_ID=%q\n' "$access_key_id"
printf 'export AWS_SECRET_ACCESS_KEY=%q\n' "$secret_access_key"
printf '\nCleanup after the evaluation (run as an administrator):\n'
printf 'aws iam delete-access-key --user-name %q --access-key-id %q\n' "$user_name" "$access_key_id"
printf 'aws iam delete-user-policy --user-name %q --policy-name %q\n' "$user_name" "$policy_name"
printf 'aws iam delete-user --user-name %q\n' "$user_name"
printf '# Review and delete only mutandae-* Secrets Manager secrets created for this evaluation.\n'
