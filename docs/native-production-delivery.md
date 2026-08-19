# Native production delivery record

This document records the delivery of Mutandae to the native `belacca-native` K3s
cluster. It is intentionally detailed: the deployment crossed a private source
repository, a public GHCR runtime image, Flux, cert-manager, Cloudflare DNS,
Traefik, and Kyverno admission. The final result is working, but several
interfaces had to be made compatible.

## Final result

- Source repository: private `macel94/mutandae`.
- Runtime image: public `ghcr.io/macel94/mutandae`.
- Cluster: `belacca-native`, three K3s nodes.
- Flux source: `flux-system/mutandae`, private SSH GitRepository.
- Flux application: `flux-system/mutandae`, path `./deploy/k3s`.
- Runtime namespace: `mutandae`.
- Public hosts:
  - `https://mutandae.com`
  - `https://preview.mutandae.com`
- Both hosts serve the same Mutandae deployment. HTTP redirects to HTTPS.
- Certificate: `mutandae-tls`, issued by `letsencrypt-cloudflare`, covering both
  hostnames.
- Source-side delivery history:
  - `4ed7eb0` — fixed valid SLSA predicate generation and legacy Cosign output.
  - `7347e2a` — first generated immutable image deployment pin.
  - `c773943` — added this delivery record.
- The current generated image tag and digest are the values in
  [`deploy/k3s/kustomization.yaml`](../deploy/k3s/kustomization.yaml). That
  file is authoritative because each successful publish may replace the
  generated pin.
- The cluster-side policy and rollout record is in
  `belacca-gitops/docs/MUTANDAE-NATIVE-DELIVERY.md`.

## Problems solved

### 1. Private source access had to be separate from runtime image access

The source repository is private, while the cluster should pull the runtime
image without a registry Secret. The solution was deliberately split:

- a read-only GitHub deploy key for Flux source access;
- an encrypted SOPS Secret in `belacca-gitops` for the SSH key, public key, and
  GitHub `known_hosts` entry;
- a public GHCR runtime package for anonymous cluster pulls;
- no source credentials, registry credentials, Cloudflare token, or age private
  key in this repository.

The GitHub deploy key is a source-access credential only. It does not grant the
cluster access to GitHub Actions or package publishing.

### 2. GitHub Artifact Attestation was not available for this source repository

The existing `belacca.com` and `pong` workflows use GitHub's native Artifact
Attestation actions. Their Kyverno rules use the corresponding
`type: SigstoreBundle` verifier and work correctly.

Mutandae could not use that storage path because GitHub does not provide
Artifact Attestation storage for this user-owned private repository in the
required way. Mutandae therefore uses keyless Cosign/Sigstore attestations,
with GitHub OIDC and Rekor:

- SLSA provenance;
- CycloneDX SBOM;
- native-production vulnerability decision.

The Kyverno identity is restricted to:

```text
issuer:  https://token.actions.githubusercontent.com
subject: https://github.com/macel94/mutandae/.github/workflows/ci.yml@refs/heads/main
rekor:   https://rekor.sigstore.dev
```

This is a different supply-chain format from the working `belacca.com` and
`pong` format, even though both are Sigstore-based.

### 3. Cosign's new bundle layout was not discoverable by this cluster

The first Cosign workflow used the newer Sigstore bundle format. The image had
valid signatures when checked directly with Cosign, but GHCR stored the
attestations in an OCI index under a `sha256-<image-digest>` tag. GHCR returned
`MANIFEST_UNKNOWN` for the OCI 1.1 `/referrers/<digest>` endpoint for that
image.

Kyverno v1.18.2's OCI 1.1 path could not discover those artifacts. The result
was misleading but accurate from Kyverno's point of view:

```text
no matching attestations
```

The final workflow explicitly uses the legacy Cosign attachment format:

```text
--new-bundle-format=false
--use-signing-config=false
```

This produces the legacy `sha256-<image-digest>.att` attachment that Kyverno's
standard Cosign verifier reads. The final `.att` manifest contains three DSSE
layers, one for each required attestation.

### 4. The Kyverno verifier type was initially wrong for Cosign

`belacca.com` and `pong` correctly use:

```yaml
type: SigstoreBundle
```

That is correct for GitHub Artifact Attestation bundles. It is not the correct
outer verifier for the Mutandae legacy Cosign attachments. Mutandae uses:

```yaml
type: Cosign
```

The attestation matcher uses the modern `type` field rather than deprecated
`predicateType`:

```yaml
attestations:
  - type: https://slsa.dev/provenance/v1
```

The final policies preserve `required: true`, `failureAction: Enforce`,
digest verification, keyless identity checks, and all predicate conditions.
No admission control was weakened to make the deployment pass.

### 5. The SBOM type had to match the actual in-toto statement

The Cosign command uses the convenient alias:

```text
--type cyclonedx
```

Cosign emits the canonical in-toto predicate URI:

```text
https://cyclonedx.org/bom
```

The policy therefore matches the URI, not the CLI alias. The SBOM condition
still requires:

```yaml
key: "{{ bomFormat }}"
value: CycloneDX
```

### 6. The SLSA input was initially shaped as a complete statement

The first workflow wrote a complete in-toto statement containing `_type`,
`subject`, `predicateType`, and `predicate`, then passed that file to
`cosign attest`.

`cosign attest` itself creates the outer in-toto statement. Passing a complete
statement caused the resulting legacy attachment to contain a nested
statement:

```text
predicate.predicate.buildDefinition
```

Kyverno's condition expects the normal predicate shape:

```text
predicate.buildDefinition.buildType
```

Kyverno consequently reported:

```text
Unknown key "buildDefinition" in path
```

The workflow now writes only the SLSA predicate object:

```json
{
  "buildDefinition": { ... },
  "runDetails": { ... }
}
```

Cosign supplies the outer statement and predicate type. The final attachment
was decoded and verified to contain:

- `https://slsa.dev/provenance/v1`, with
  `predicate.buildDefinition.buildType` equal to
  `https://actions.github.io/buildtypes/workflow/v1`;
- `https://cyclonedx.org/bom`, with `bomFormat: CycloneDX`;
- `https://belacca.com/attestations/vulnerability/v1`, with the native
  production severity and unfixed-vulnerability conditions.

### 7. The image needed a new digest after correcting attestation generation

Changing only the workflow would reuse the same image digest. That can leave
old malformed attestations attached to the same immutable image and makes
verification ambiguous.

The workflow now passes `BUILD_SHA` to the Docker build, and each published
image records it as the non-secret OCI revision label:

```dockerfile
LABEL org.opencontainers.image.revision=$BUILD_SHA
```

The corrected workflow published a fresh digest and wrote it to
`deploy/k3s/kustomization.yaml`. Future generated commits may update that
value without changing the compatibility contract.

### 8. Generated deployment commits race with local source checkouts

The publish workflow changes the source repository after the human source
commit by committing the immutable image tag and digest. A local checkout can
therefore be behind `origin/main` immediately after a workflow succeeds.

The safe sequence is:

1. push the human source commit;
2. wait for CI and the generated deployment commit;
3. fetch `origin/main` again;
4. use the generated deployment commit and its pinned digest as the Flux input.

During this delivery, stale local history caused a non-fast-forward push. It
was resolved by rebasing the workflow commit onto the generated deployment
commit. No generated pin was overwritten.

### 9. Flux dependency ordering and retry windows obscured failures

The cluster root owns the namespace, policies, routing, and child Flux
Kustomizations. The Mutandae child depends on `flux-system` and
`native-image-policy`.

The namespace was deliberately moved to GitOps ownership so the application
overlay does not fight the cluster repository. The root Kustomization also
needed the namespace available before namespaced certificate and routing
resources were reconciled.

When Kyverno temporarily returned an admission webhook `EOF`, Flux entered its
normal retry state. The correct response was to inspect controller and webhook
health, wait for the control plane to recover, and explicitly reconcile the
root and dependency chain. Direct `kubectl apply` or `kubectl set image` was
not used as a permanent fix.

### 10. TLS and DNS had to use the existing native contracts

The deployment reuses the cluster's existing infrastructure:

- existing `letsencrypt-cloudflare` ClusterIssuer;
- existing `cert-manager/cert-manager-cloudflare` Secret;
- Cloudflare DNS-01 challenges;
- Traefik HTTP redirect and HTTPS routes;
- three DNS-only A records per hostname, pointing to the native edge IPs.

No second Cloudflare Secret was created and no secret value was committed.

## Verification performed

The final deployment was checked at every layer:

```text
Flux GitRepository mutandae:       main@sha1:7347e2ae — Ready
Flux Kustomization mutandae:       main@sha1:7347e2ae — Ready/Healthy
Deployment:                        Available=True
Pod:                               1/1 Running
Image:                             immutable tag and digest
Certificate mutandae-tls:          Ready=True
mutandae.com HTTP:                 301 to HTTPS
preview.mutandae.com HTTP:         301 to HTTPS
https://mutandae.com:               200
https://preview.mutandae.com:       200
```

The existing `https://belacca.com` endpoint was also checked after rollout and
remained operational.

## Future Kyverno decision

Kyverno should remain installed. Removing it would remove the cluster's
admission enforcement for:

- image provenance;
- SBOM presence and format;
- vulnerability decisions;
- immutable image digests;
- the existing platform policy set.

The current installation is Kyverno `v1.18.2` from chart `3.8.2`, and it now
verifies Mutandae successfully. A `v1.19.0` release candidate exists, but an
upgrade is not required to solve this incident and should not be performed
blindly in production.

For a future upgrade:

1. test the candidate in a disposable or staging cluster;
2. verify both GitHub Artifact Attestation and legacy Cosign policies;
3. test GHCR OCI 1.1 referrer discovery separately from legacy attachments;
4. upgrade the Flux HelmRelease, not the cluster with an ad hoc Helm command;
5. reconcile and verify all existing workloads before changing Mutandae's
   publishing format;
6. retain legacy Cosign output until the new path is proven end to end.

The lasting lesson is not to copy the `belacca.com`/`pong` `SigstoreBundle`
configuration to every producer. First identify the producer's attestation
format, registry storage layout, and the exact verifier implementation running
in the cluster.
