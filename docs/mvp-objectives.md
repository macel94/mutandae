# MVP objectives

## MVP thesis

The MVP must prove that one control plane can provide a coherent lifecycle and governance story for machine identities and renewable credentials.

It does not need to solve every cloud, every identity pattern, or every enterprise workflow. It needs to prove a coherent Azure-first slice and make the provider-neutral boundary extensible to AWS IAM and GCP IAM.

## MVP scope

### Providers

- Microsoft Azure / Microsoft Entra ID
- AWS IAM
- GCP IAM

### Primary lifecycle

The first complete flow should cover:

1. Register or provision a machine identity.
2. Attach an owner and workload/application context.
3. Define a lifecycle and renewal policy.
4. Track activation and expiry.
5. Schedule and execute a renewal/rotation workflow.
6. Verify the resulting provider state.
7. Correlate the run with audit events.
8. Revoke or decommission the identity through an explicit lifecycle transition.

### User experience

The frontend should help a user answer:

- Which machine identities exist?
- Which provider and environment do they belong to?
- Who owns them?
- What application or workload uses them?
- What is expiring soon?
- Is renewal healthy?
- What happened during the last rotation?
- What should be retired?

The experience should communicate lifecycle and governance, not simply mirror raw provider state.

## Public/open-source MVP surface

The public repository should contain enough real functionality to be credible and evaluable:

- the open-source frontend;
- the shared lifecycle/rotation protocol;
- public domain abstractions and schemas;
- lifecycle state transitions;
- audit/event contracts;
- a minimal control-plane backend shell;
- credential-less simulators and standard-library real adapters for the covered
  identity classes;
- example workflows and adapter contract tests;
- documentation showing how a third-party provider adapter fits the boundary.

The open layer must be runnable and coherent. It must not be a fake CRUD facade around a hidden product.

## Commercial MVP surface

A managed offering should retain commercially meaningful operating value:

- secure managed execution;
- deployment-specific credential handling and delivery;
- provider-specific maintenance, edge cases, failure recovery, and operational
  safeguards;
- advanced integrations and enterprise controls.

The public release already includes standard-library provider mechanics for the
covered identity classes. Commercial value can come from secure operations,
maintenance, broader coverage, and reliability rather than withholding the
lifecycle concept.

## MVP non-goals

The MVP should not attempt to become:

- a full multi-cloud IAM suite;
- a universal secrets manager;
- a feature-complete Vault alternative;
- a complete human identity governance product;
- a full PAM platform;
- a generalized workflow automation system;
- a broad catalog of every Azure credential type.

## MVP success criteria

The MVP is successful when all of the following are true:

### Product

- A user can understand the lifecycle state of an Azure machine identity from one interface.
- Ownership and accountability are visible.
- Expiry and renewal health are actionable.
- A complete renewal/rotation run can be inspected from initiation to verified outcome.
- Retirement/decommissioning is represented as an explicit workflow, not an informal deletion.

### Architecture

- The public protocol is provider-neutral and versioned.
- The public backend is deliberately small.
- A provider adapter boundary keeps provider mechanics out of the protocol and frontend.
- The frontend does not depend directly on Azure SDK details.
- Audit correlation exists across lifecycle actions.

### Open-core strategy

- An evaluator can run the open-source layer locally.
- The public layer demonstrates real lifecycle semantics.
- The commercial layer has a clear reason to exist.
- Commercial value comes from secure operations, provider maintenance, and reliability, not merely from withholding the concept.

### Security

- Plaintext exposure is minimized in the public architecture.
- Trust boundaries are documented.
- The system does not make impossible operator-access claims.
- Failed renewals produce visible, auditable outcomes.

## Suggested MVP milestones

> **Progress** — The protocol, protocol-native control-plane shell, HTMX
> frontend, credential-less multi-cloud simulators, standard-library real
> adapters, and environment-gated real-cloud evaluation are shipped in this
> repository. The former private Azure boundary is now public for the covered
> identity class; broader managed operations and identity coverage remain on the
> public roadmap.

### Milestone 1 — Protocol and domain model

- Define lifecycle states and valid transitions.
- Define identity, provider binding, ownership, policy, rotation-run, and event schemas.
- Define protocol versioning and conformance rules.

### Milestone 2 — Open control-plane shell

- Implement minimal persistence and APIs.
- Add lifecycle transition validation.
- Add audit event recording.
- Keep the credential-less simulator and consuming-side adapter boundary usable
  for local development.

### Milestone 3 — Public frontend

- Identity inventory.
- Ownership view.
- Expiry/renewal dashboard.
- Rotation-run detail.
- Lifecycle history and audit timeline.

### Milestone 4 — Provider boundary and real execution

- Define the consuming-side adapter contract.
- Connect the standard-library Azure/Entra, AWS IAM, and GCP IAM adapters.
- Validate provider-state verification and failure handling.

### Milestone 5 — Vertical-slice validation

- Run complete Azure, AWS, and GCP flows from discovery through rotation and
  retirement.
- Test failure and recovery paths.
- Validate the open-source/commercial boundary.
- Document the product demo and evaluator setup.
