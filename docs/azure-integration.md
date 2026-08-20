# Interactive Azure / Entra integration

Mutandae has two modes:

1. The public lifecycle dashboard uses a synthetic Azure / Entra adapter and
   Redis-backed demo state.
2. The Configuration page can open a short-lived session against an Azure tenant
   that you control.

The second mode is intentionally opt-in. It does not replace the synthetic
inventory and it does not put customer credentials into the lifecycle snapshot.

## Required permission

The client application supplied to the Configuration page needs exactly this
Microsoft Graph **application permission**:

```text
Application.ReadWrite.OwnedBy
```

Grant admin consent for that permission in the tenant before connecting. This
permission is the ownership boundary: Graph permits mutations only for
applications owned by the calling client. Mutandae does not accept a browser
supplied owner field as an authorization decision.

The interactive path uses Microsoft Graph to:

- list application metadata;
- create an application, which is owned by the creating principal where
  supported by the Graph application-permission flow;
- add a generated password credential;
- remove that credential with `removePassword`; and
- list safe password credential metadata such as key ID, hint, and expiry.

Microsoft Graph returns `secretText` only from `addPassword`. It cannot be read
back later from Graph.

## Optional Key Vault retrieval

Without a vault, copy the generated secret immediately. Mutandae will not store
it, and Graph cannot recover it later.

To retrieve a generated value later, configure an **existing** Azure Key Vault:

- URL: `https://<vault-name>.vault.azure.net`
- optional secret prefix, such as `mutandae`
- optional owner object ID metadata

The supplied client also needs Key Vault data-plane permission independent of
Graph:

- `Key Vault Secrets Officer` to write generated values;
- `Key Vault Secrets User` to read values; or
- `Key Vault Secrets Officer` for both write and read.

Mutandae does not create vaults, assign roles, or change Key Vault policy. The
vault reference records the secret name, version, expiry, application object ID,
credential key ID, and optional owner metadata as tags.

**Important owner limitation:** a client-credential session identifies the
calling application, not a human browser user. A comma-separated owner list is
metadata only. To guarantee that only selected human owners can retrieve a
secret, configure Azure RBAC/delegated Entra authentication outside this demo;
do not rely on the form field alone.

## Credential handling

The page uses:

- HTTPS as the expected transport;
- a write-only client password field;
- an opaque HttpOnly integration session cookie;
- a separate CSRF token for state-changing routes;
- server-derived connection throttling;
- a ten-minute maximum in-memory session;
- explicit disconnect and process-shutdown cleanup;
- `Cache-Control: no-store` on protocol responses; and
- security headers including a restrictive Content Security Policy.

The client secret, Graph bearer token, and generated secret plaintext are never
written to:

- Redis snapshots;
- Redis integration event receipts;
- pub/sub payloads;
- lifecycle identities or events;
- application logs; or
- normal configuration/session responses.

The only intentional plaintext responses are:

- the immediate Graph secret creation response when no vault is selected; and
- an explicit vault read response.

## Post-demo cleanup

After testing against a real tenant:

1. Use **Invalidate** for every generated application credential.
2. In the Entra admin center, invalidate the temporary client secret used to
   connect Mutandae.
3. Remove the Graph admin consent if the client application is no longer used.
4. If Key Vault was enabled, delete or disable the demo secret versions using
   your normal vault retention policy.
5. Confirm the client application has no remaining unnecessary permissions.

Do not paste production credentials into screenshots, issue reports, shell
history, or support requests.

## Protocol examples

Get the safe requirement document:

```sh
curl -sS https://mutandae.example/api/v1/integration/requirements
```

Connect requires the CSRF cookie/header pair established by `GET /configuration`.
The JSON request is write-only and should be sent only over HTTPS:

```json
{
  "tenant_id": "00000000-0000-0000-0000-000000000000",
  "client_id": "11111111-1111-1111-1111-111111111111",
  "client_secret": "temporary-value",
  "vault": {
    "url": "https://example.vault.azure.net",
    "secret_prefix": "mutandae",
    "owner_object_ids": ["22222222-2222-2222-2222-222222222222"]
  }
}
```

Create an application:

```json
{"display_name":"mutandae-real-tenant-demo"}
```

Create a secret and store it in the configured vault:

```json
{
  "application_object_id":"<owned-object-id>",
  "display_name":"mutandae-demo-secret",
  "store_in_vault":true
}
```

The response contains the versioned vault reference, not plaintext. Read the
exact version later with the application object ID, Graph credential key ID,
and returned vault version:

```json
{
  "application_object_id":"<owned-object-id>",
  "key_id":"<credential-key-id>",
  "version":"<vault-version>"
}
```

Invalidate the Graph credential:

```json
{
  "application_object_id":"<owned-object-id>",
  "key_id":"<credential-key-id>"
}
```

Every operation returns a correlation ID and indicates whether its redacted
Redis receipt was published. Redis `MULTI/EXEC` makes the receipt and pub/sub
notification atomic inside Redis; it cannot make the remote Azure mutation and
Redis write one distributed transaction. Invalidation revokes the Graph
credential first and then disables the exact current Key Vault version when
possible; a vault-side failure is reported as a partial failure rather than
silently claimed successful.

## Deployment note

The application pod must be allowed outbound TCP/443 to Microsoft identity,
Microsoft Graph, and any configured Key Vault endpoint. The existing hosted
Redis policy is intentionally default-deny and must be extended in the owning
`belacca-gitops` repository with a reviewed HTTPS egress rule or the interactive
path will fail closed while the synthetic demo continues to work.
