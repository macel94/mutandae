# CI and real-cloud evaluation

Mutandae's normal CI runs formatting, tests, race detection, vet, the Go build,
container build, vulnerability-decision checks, and Docker Compose parsing.
The immutable-image publish job remains restricted to `main` and records the
image digest in the GitOps manifest.

The separate `.github/workflows/realclouds.yml` workflow runs at 03:17 UTC
each night and can also be started with `workflow_dispatch`. It skips unless
at least one `ENABLE_*_EVAL` repository or organization variable is exactly
`true`. It runs only:

```sh
MUTANDAE_EVAL=1 go test -tags=realclouds -count=1 ./internal/eval/...
```

The evaluator is destructive to its disposable targets: it discovers, rotates,
and retires identities under the configured `MUTANDAE_EVAL_PREFIX` (default
`mutandae-eval`). Do not point it at production identities.

## GitHub variables and secrets

Set these as repository or environment variables. Environment protection and
required reviewers are recommended for every real-cloud environment.

| Name | Kind | Purpose |
| --- | --- | --- |
| `ENABLE_AWS_EVAL` | variable | Set to `true` to enable AWS OIDC and include AWS evaluation. |
| `AWS_EVAL_ROLE_ARN` | variable | Disposable AWS role assumed through GitHub OIDC. |
| `AWS_ACCOUNT_ID` | variable | Account containing the `mutandae-eval-*` IAM targets. |
| `AWS_REGION` | variable | AWS region, normally `us-east-1`. |
| `ENABLE_GCP_EVAL` | variable | Set to `true` to enable GCP WIF authentication and include GCP evaluation. |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | variable | Full WIF provider resource name. |
| `GCP_EVAL_SERVICE_ACCOUNT` | variable | Service account impersonated by the WIF action. |
| `GCP_PROJECT_ID` | variable | Disposable GCP evaluation project. |
| `GCP_REGION` | variable | GCP region, normally `us-central1`. |
| `ENABLE_AZURE_EVAL` | variable | Set to `true` to enable Azure OIDC CLI login and Azure evaluation. |
| `AZURE_AZ_CLIENT_ID` | variable | Application/client ID with the GitHub federated credential. The `AZ` segment distinguishes this from the adapter's exported `AZURE_CLIENT_ID`. |
| `AZURE_TENANT_ID` | variable | Entra tenant for the evaluation application. |
| `MUTANDAE_EVAL_PREFIX` | variable | Disposable identity prefix; default `mutandae-eval`. |
| `GCP_SERVICE_ACCOUNT_KEY_JSON` | secret | Optional/currently required private JSON key for the GCP adapter's real API calls. |
| `AZURE_CLIENT_SECRET` | secret | Optional/currently required client secret for the Azure Graph adapter's real API calls. |

There are deliberately no AWS access-key secrets in the workflow. The AWS
credentials action exports short-lived `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` after OIDC role assumption.
The workflow passes the Azure and GCP secrets only to the final evaluator step.
Never print those variables or enable shell tracing.

## AWS trust setup

Create the GitHub OIDC provider in the AWS account if it is not present:

- issuer: `https://token.actions.githubusercontent.com`
- audience: `sts.amazonaws.com`

Create a disposable role whose trust policy is restricted to this repository
and the `main` ref. Replace `OWNER/REPO` and the account id; do not use `*` for
`sub`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<AWS_ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:OWNER/REPO:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

Attach an inline or managed permission policy containing only the evaluator's
required IAM actions (`iam:ListUsers`, `iam:GetUser`,
`iam:ListAccessKeys`, `iam:CreateAccessKey`,
`iam:UpdateAccessKey`, `iam:DeleteAccessKey`, `iam:DeleteLoginProfile`, and
`iam:TagUser`) with target resources limited to `user/mutandae-eval-*` where
AWS supports resource scoping. Any Secrets Manager permissions must be limited
to `mutandae-eval-*` secret names/ARNs. Start from
`scripts/aws-governor-policy.json`, then narrow the namespace from
`mutandae-*` to `mutandae-eval-*` for CI.

Verify with `aws sts get-caller-identity` in a private, approved test run, and
remove the role, keys, test users, and test secrets when the evaluation is
closed.

## GCP Workload Identity Federation setup

Create a WIF pool and OIDC provider in a disposable project or security host
project. The provider should map the GitHub subject and repository and reject
all other repositories/refs:

```sh
gcloud iam workload-identity-pools create mutandae-github \
  --project=PROJECT_ID --location=global \
  --display-name='Mutandae GitHub Actions'

gcloud iam workload-identity-pools providers create-oidc mutandae \
  --project=PROJECT_ID --location=global \
  --workload-identity-pool=mutandae-github \
  --issuer-uri=https://token.actions.githubusercontent.com \
  --attribute-mapping='google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.ref=assertion.ref' \
  --attribute-condition="assertion.repository == 'OWNER/REPO' && assertion.ref == 'refs/heads/main'"
```

Grant the WIF principal permission to impersonate the disposable evaluation
service account. Use the numeric project number in the principal resource:

```sh
gcloud iam service-accounts add-iam-policy-binding \
  mutandae-governor@PROJECT_ID.iam.gserviceaccount.com \
  --project=PROJECT_ID \
  --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/mutandae-github/attribute.repository/OWNER/REPO"
```

Grant that service account only the custom evaluator role needed to list and
rotate `mutandae-eval-*` service-account keys and access the correspondingly
scoped Secret Manager names. A condition such as
`resource.name.startsWith("projects/PROJECT_NUMBER/secrets/mutandae-eval-")`
should be used where the API supports it. The `google-github-actions/auth@v2` step creates a
short-lived federated credential file for CLI use.

## Azure / Entra federated credential setup

Create or select a disposable Entra application and service principal. Add a
federated identity credential restricted to this repository and the `main` ref:

```sh
az ad app federated-credential create --id AZURE_CLIENT_ID --parameters '{
  "name": "mutandae-github-main",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:OWNER/REPO:ref:refs/heads/main",
  "description": "Mutandae real-cloud workflow on main",
  "audiences": ["api://AzureADTokenExchange"]
}'
```

Use `azure/login@v2` with `client-id` and `tenant-id`. If the tenant has no
Azure subscription, the workflow uses `allow-no-subscriptions: true`. Grant
only the Azure permissions needed by the disposable smoke/evaluation target.
The Azure governor provisioning script documents the Graph
`Application.ReadWrite.OwnedBy` permission and admin-consent cleanup.

## Current limitations

- **AWS:** `aws-actions/configure-aws-credentials@v4` exchanges the GitHub OIDC
  token for short-lived role credentials. The current AWS adapter uses those
  exported SigV4 environment variables, so AWS can run without static keys.
- **Azure:** `azure/login@v2` is genuinely OIDC-federated and is useful for
  Azure CLI smoke checks. The current stdlib Graph adapter, however, obtains
  its client-credentials token with `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and
  `AZURE_CLIENT_SECRET`; `azure/login` cannot manufacture that client secret.
  The workflow therefore documents and optionally passes the static Azure
  secret until the adapter supports a federated access-token boundary.
- **GCP:** `google-github-actions/auth@v2` uses WIF and creates an external
  account credential file for gcloud/Google SDKs. The current stdlib adapter
  reads `GCP_SERVICE_ACCOUNT_KEY_JSON` (or a file containing a private key) and
  signs its JWT client assertion itself. WIF token exchange is roadmap work for
  the adapter, so actual GCP evaluation still needs the optional static JSON
  key secret. Do not enable GCP evaluation without it.

These limitations are intentional documentation, not a claim that static
credentials are equivalent to federation. Prefer OIDC/WIF for all new paths
and use the static compatibility secrets only as disposable, narrowly scoped
migration inputs.

## Security and revocation checklist

- Use separate disposable principals and projects/accounts/tenants for CI.
- Restrict all mutable names to `mutandae-eval-*`; do not run against ordinary
  inventory identities.
- Keep `id-token: write` at workflow/job scope only where federation is used;
  keep `contents: read` as the source permission.
- Require environment approval for manual runs and serialize real-cloud runs;
  the workflow has a single concurrency group.
- Delete rotated keys, created users/service accounts/applications, native
  vault secrets, WIF providers, federated credentials, and IAM role bindings
  after an evaluation. Revoke `AZURE_CLIENT_SECRET` and delete the
  `GCP_SERVICE_ACCOUNT_KEY_JSON` secret if either compatibility path is no
  longer needed.
- Treat every one-time cloud credential as compromised if it appears in shell
  history, a log, an issue, or a screenshot; revoke and replace it immediately.
