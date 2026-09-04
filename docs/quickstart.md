# Mutandae quickstart

This is the shortest path to a local Mutandae preview. It uses Docker Compose,
Redis, and an intentionally disposable HashiCorp Vault dev server. No cloud
account or cloud credential is needed.

## Prerequisites

- Docker Engine with Docker Compose v2 (`docker compose version`)
- A terminal in the repository root

## Start the preview

```sh
docker compose up --build
```

The first build downloads the Go and Alpine build layers and may take a few
minutes. Leave this terminal running, then open
[http://localhost:8080](http://localhost:8080).

You will see:

- the Mutandae dashboard and lifecycle controls;
- three simulated cloud inventories: Azure / Entra ID, AWS IAM, and GCP IAM;
- seeded identities with lifecycle state, expiry, ownership, and attention
  status; and
- audit events after discovery, rotation, or retirement actions.

The default preview has no authentication requirement. It is a local demo
configuration, not an access-control boundary.

Check the health endpoints if needed:

```sh
curl -fsS http://localhost:8080/livez
curl -fsS http://localhost:8080/readyz
```

## Audit output

The application writes JSONL audit events to `/data/audit.jsonl` inside the
`mutandae` container. In the base Compose file, `/data` is the named Docker
volume `mutandae-data`, so inspect it without exposing it on a host port:

```sh
docker compose exec mutandae sh -c 'ls -l /data && tail -n 20 /data/audit.jsonl'
```

To make that file visible locally, copy the example override before starting
(or restart after copying it). Keep the bind-mounted directory outside the
repository so `Dockerfile`'s build context cannot contain audit data:

```sh
export MUTANDAE_AUDIT_DIR="$HOME/.local/share/mutandae"
mkdir -p "$MUTANDAE_AUDIT_DIR"
cp docker-compose.override.yml.example docker-compose.override.yml
docker compose up --build
```

The file then lands at
`$MUTANDAE_AUDIT_DIR/audit.jsonl`. Keep that directory private and remove the
local override when finished:

```sh
rm -f docker-compose.override.yml
rm -rf "$MUTANDAE_AUDIT_DIR"
unset MUTANDAE_AUDIT_DIR
```

## Optional real Azure / Entra connection

The Compose file deliberately does **not** pass cloud credentials. Read the
[Azure / Entra integration guide](azure-integration.md) first, use a disposable
least-privilege tenant application, and provide credentials through a private
local override or an explicit `docker compose run -e ...` invocation. Never
put the values in the committed Compose file or `.env.example`.

The current interactive path requires `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and
`AZURE_CLIENT_SECRET`; `AZURE_KEY_VAULT_URL` is optional for native vault
retrieval. For a private local override, use placeholders from your shell
environment, not literal secrets:

```yaml
services:
  mutandae:
    environment:
      AZURE_TENANT_ID: "${AZURE_TENANT_ID:?set AZURE_TENANT_ID privately}"
      AZURE_CLIENT_ID: "${AZURE_CLIENT_ID:?set AZURE_CLIENT_ID privately}"
      AZURE_CLIENT_SECRET: "${AZURE_CLIENT_SECRET:?set AZURE_CLIENT_SECRET privately}"
      AZURE_KEY_VAULT_URL: "${AZURE_KEY_VAULT_URL:-}"
```

Do not use a real cloud connection for the five-minute demo unless you have
reviewed the permission and cleanup steps in the integration guide.

## Stop and remove the preview

Stop the foreground process with `Ctrl-C`, or use another terminal:

```sh
docker compose down
```

The named Redis and audit volumes remain for the next preview. To remove those
volumes and all local audit data as well:

```sh
docker compose down -v
```

The Compose Vault is dev mode and in-memory, so its secrets disappear whenever
that container is removed or restarted. The audit volume is separate and is
not a production backup mechanism.

> **What this is / is not**
>
> **This is:** a local, dependency-light product preview with simulated Azure,
> AWS, and GCP lifecycle behavior, Redis-backed state, an in-memory dev Vault,
> and an auditable JSONL file sink.
>
> **This is not:** a production deployment, a cloud permission boundary, a
> durable Vault installation, or an authentication system. Authentication is
> off by default in this preview. The dev Vault uses a disposable root token;
> never put real secrets into it, never publish its port, and never expose this
> Compose stack directly to the internet.
