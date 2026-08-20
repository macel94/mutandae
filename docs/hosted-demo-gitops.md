# Hosted demo and GitOps replication

## Public entry points

The native deployment currently exposes:

- `https://mutandae.com` — live demo
- `https://preview.mutandae.com` — preview/sandbox demo

Both hosts are intended to be easy-to-follow public simulators. The application
has a safe read-only configuration page at `/configuration` and a matching
protocol endpoint at `/api/v1/configuration`.

## Runtime model

The two deployments use the same public image and one dedicated Redis instance,
but they are isolated by application environment:

```text
mutandae-live    --REDIS_URL--> Redis
  prefix: mutandae:live

mutandae-preview --REDIS_URL--> Redis
  prefix: mutandae:preview
```

Redis stores protocol-native JSON snapshots and publishes invalidation messages
on each environment's `<prefix>:changes` channel. It is a fast temporary demo
store, not a durable event log. Restarting Redis or deleting an environment
snapshot resets that environment to the simulated Azure seed on next startup.
Do not put real Azure credentials, customer data, or secrets into the demo.

PostgreSQL is intentionally not provisioned in this iteration. The application
owns the `lifecycle.Repository` boundary so a future PostgreSQL repository can
add transactional durability, migrations, immutable event storage, and stronger
concurrency controls without changing the frontend or protocol.

## Repository ownership

| Change | Repository | Reason |
|---|---|---|
| Go code, templates, image, Redis client, application env contract | `mutandae` | Application source and publish workflow |
| Redis StatefulSet/PVC/Secret, preview/live Deployments, Services, routing, TLS, NetworkPolicies, backup contract, Flux root overlay | `belacca-gitops` | Cluster resources and GitOps source of truth |
| Parent submodule pointer | `belacca-platform` | Workspace bookkeeping only; it never deploys by itself |

A parent push is not a deployment. Push the owning child repository first, then
wait for the application image publish/generated deployment commit or the
GitOps commit to reconcile, and verify Flux plus live behavior.

## Reproduce on another cluster

1. **Application repository**
   - Set `REDIS_URL` and `MUTANDAE_ENVIRONMENT` in the deployment environment.
   - Run `go test ./...`, `go test -race ./...`, `go vet ./...`, and `git diff --check`.
   - Push `mutandae/main`.
   - Wait for CI to publish the immutable GHCR image and generated image-pin commit.

2. **GitOps repository**
   - Copy the `clusters/<cluster>/mutandae/` overlay pattern.
   - Extend the existing root-owned `clusters/belacca-production/mutandae/`
     overlay for the dedicated Redis workload; preserve unique Redis key prefixes.
   - Create the Redis password as SOPS-encrypted Secret data; never commit it
     plaintext.
   - Set the preview/live image tag and digest from the application publish
     workflow, not from a mutable tag.
   - Add preview/live Ingress and cert-manager DNS names in the cluster-owned
     routing/TLS resources.
   - Render with `kubectl kustomize` and run repository validators before push.

3. **Promotion and proof**
   - Push `belacca-gitops/main`.
   - Reconcile the Flux source and affected Kustomizations.
   - Verify the GitRepository and Kustomization revisions, Redis StatefulSet and
     PVC readiness, both application Deployments and image digests, NetworkPolicy
     connectivity, and `/livez`, `/readyz`, `/configuration`, and `/api/v1/` on
     both public hosts.
   - Confirm a preview rotation/reset does not change live data. If the UI does
     not yet expose reset, verify isolation by using distinct environment
     prefixes and controlled lifecycle actions.

## Verification evidence

The hosted rollout was verified on the native cluster:

- Flux root revision: `main@sha1:ac991d1d`.
- Mutandae application revision: `main@sha1:c54535f`.
- Application image: `ghcr.io/macel94/mutandae:sha-0e8f612f2066af3e30e69c9acc302539bcbac5c3@sha256:4f1d5bfbef53a2395cbb4930230c7f07ab190572b2d203fa478de3be138b552f`.
- Redis StatefulSet: `1/1` ready.
- Redis PVC: `5Gi`, `Bound`, Longhorn-backed.
- Live and preview Deployments: `1/1`, using the same immutable image digest.
- All three native edge IPs returned `200` for both hostnames after the
  host-network Traefik NetworkPolicy sources were allowed.
- `/api/v1/configuration` reported `live` and `preview` respectively, with
  `persistence: redis` and `read_only: true`.
- A preview rotation changed the preview identity response while the live
  identity response remained unchanged.
- Live and preview `/api/v1/integration/requirements` both report exactly
  `Application.ReadWrite.OwnedBy` and the documented optional Key Vault roles.
- All three native edge IPs returned HTTP 200 for both live and preview API
  discovery requests.
- `TestRedisRepositoryRealServerSnapshotIsolationAndPubSub` and
  `TestRedisEventPublisherRealServerReceiptAndNotification` passed through a
  temporary port-forward against the real Redis Service using unique
  `mutandae:test:<run>` prefixes; cleanup scans and deletes only matching
  prefixes.

## Local Redis

For local testing, run a disposable Redis instance and use a separate prefix:

```sh
docker run --rm --name mutandae-redis -p 6379:6379 redis:7-alpine
REDIS_URL=redis://localhost:6379/0 \
MUTANDAE_ENVIRONMENT=preview \
go run ./cmd/mutandae
```

The application does not accept a Redis password through the public UI. Supply
credentials only through the deployment Secret/environment boundary.
