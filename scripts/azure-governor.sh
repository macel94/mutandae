#!/usr/bin/env bash
# Provision the least-privilege Microsoft Graph governor used by Mutandae.
#
# DANGER: This script changes an Entra tenant. Run it only from a trusted,
# private terminal with an administrator account. The client secret is printed
# exactly once by Azure CLI; capture it securely and rotate/revoke it after use.
# No secret is written to a file by this script.
set -euo pipefail
# Do not let a caller's inherited xtrace setting print credential arguments.
set +x

usage() {
	cat <<'USAGE'
Usage: scripts/azure-governor.sh [--help]

Creates or reuses the mutandae-governor app registration, requests the
Microsoft Graph Application.ReadWrite.OwnedBy application permission, asks for
admin consent, and creates a one-year client secret.

Inputs:
  AZURE_TENANT_ID  Optional tenant override; otherwise the current az account.
  MUTANDAE_AZURE_APP_NAME  Optional app display-name override.

The final AZURE_CLIENT_SECRET value is one-time output. Store it in a secret
manager, never in git, shell history, CI logs, or a shared ticket.
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

command -v az >/dev/null 2>&1 || {
	printf 'error: az (Azure CLI) is required\n' >&2
	exit 127
}

cat >&2 <<'WARNING'
DANGER: this provisions an Entra application and requests tenant-wide admin
consent for Microsoft Graph Application.ReadWrite.OwnedBy. Confirm the target
subscription/tenant before continuing. Treat the one-time secret below as a
production credential until it is captured and revoked.
WARNING

readonly graph_app_id='00000003-0000-0000-c000-000000000000'
# This is the Microsoft Graph application-role id requested by this runbook.
readonly owned_by_role_id='18a4bd3e-fce7-4b3f-ade6-10b47bf58b3a'
readonly app_name="${MUTANDAE_AZURE_APP_NAME:-mutandae-governor}"

current_tenant_id="$(az account show --query tenantId --output tsv)"
[[ -n "$current_tenant_id" ]] || {
	printf 'error: no Azure tenant; run az login or set AZURE_TENANT_ID\n' >&2
	exit 1
}
if [[ -n "${AZURE_TENANT_ID:-}" && "$AZURE_TENANT_ID" != "$current_tenant_id" ]]; then
	printf 'error: az is logged into tenant %s, not AZURE_TENANT_ID=%s\n' "$current_tenant_id" "$AZURE_TENANT_ID" >&2
	exit 1
fi
tenant_id="$current_tenant_id"

app_id="$(az ad app list --display-name "$app_name" --query '[0].appId' --output tsv)"
if [[ -z "$app_id" ]]; then
	app_id="$(az ad app create --display-name "$app_name" --query appId --output tsv)"
fi
[[ -n "$app_id" ]] || {
	printf 'error: Azure CLI did not return an application id\n' >&2
	exit 1
}

# An app registration needs a service principal before tenant consent can be
# granted. Reusing an existing one makes this safe to rerun.
if ! az ad sp show --id "$app_id" --output none >/dev/null 2>&1; then
	az ad sp create --id "$app_id" --output none >/dev/null
fi

# Verify the role catalog before requesting the permission. This intentionally
# fails closed if the Graph service principal does not expose the supplied id.
# Verification command for operators:
# az ad sp show --id 00000003-0000-0000-c000-000000000000 -o json | grep -B 8 -A 8 '18a4bd3e-fce7-4b3f-ade6-10b47bf58b3a'
graph_roles="$(az ad sp show --id "$graph_app_id" --output json)"
if ! grep -Fqi "$owned_by_role_id" <<<"$graph_roles"; then
	printf 'error: Graph app-role id %s was not found; refusing to grant permission\n' "$owned_by_role_id" >&2
	exit 1
fi

# Avoid adding a duplicate app role when this provisioning recipe is rerun.
app_permissions="$(az ad app permission list --id "$app_id" --output json)"
if ! grep -Fqi "$owned_by_role_id" <<<"$app_permissions"; then
	az ad app permission add \
		--id "$app_id" \
		--api "$graph_app_id" \
		--api-permissions "${owned_by_role_id}=Role" \
		--output none >/dev/null
fi
az ad app permission admin-consent --id "$app_id" --output none >/dev/null

# Azure returns the password only from this operation. Keep the command output
# in memory and do not enable shell tracing around it.
credential_output="$(az ad app credential reset \
	--id "$app_id" \
	--years 1 \
	--append \
	--query '[keyId, password]' \
	--output tsv)"
IFS=$'\t' read -r key_id client_secret <<<"$credential_output"
[[ -n "${key_id:-}" && -n "${client_secret:-}" ]] || {
	printf 'error: Azure CLI did not return a client secret; nothing was printed\n' >&2
	exit 1
}

printf '\nCapture this one-time credential output in a secure secret manager.\n'
printf 'export AZURE_TENANT_ID=%q\n' "$tenant_id"
printf 'export AZURE_CLIENT_ID=%q\n' "$app_id"
printf 'export AZURE_CLIENT_SECRET=%q\n' "$client_secret"
printf '\nCleanup after the evaluation (the app deletion revokes its consent):\n'
printf 'az ad app credential delete --id %q --key-id %q\n' "$app_id" "$key_id"
printf '# Remove the Graph admin consent in Entra admin center, then remove the requested permission if retaining the app:\n'
printf 'az ad app permission delete --id %q --api %q --api-permission %q\n' "$app_id" "$graph_app_id" "$owned_by_role_id"
printf 'az ad app delete --id %q\n' "$app_id"
