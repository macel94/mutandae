# MVP objectives

## MVP thesis

The MVP must prove that one control plane can provide a coherent lifecycle and governance story for machine identities and renewable credentials.

It does not need to solve every cloud, every identity pattern, or every enterprise workflow. It needs to prove one excellent Azure-first vertical slice.

## MVP scope

### Provider

- Microsoft Azure / Microsoft Entra ID

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
- a local or simulated provider adapter;
- example workflows and conformance tests;
- documentation showing how a private provider adapter fits the boundary.

The open layer must be runnable and coherent. It must not be a fake CRUD facade around a hidden product.

## Private/commercial MVP surface

The private implementation should retain commercially meaningful execution value:

- production Azure renewal implementation;
- secure managed execution;
- tenant-aware provider integration;
- credential handling and delivery mechanics;
- provider-specific edge cases;
- failure recovery and operational safeguards;
- advanced integrations and enterprise controls.

The public protocol should describe lifecycle semantics without revealing the provider-specific renewal machinery that makes the managed product reliable.

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
- A provider adapter boundary exists before private provider mechanics are added.
- The frontend does not depend directly on Azure SDK details.
- Audit correlation exists across lifecycle actions.

### Open-core strategy

- An evaluator can run the open-source layer locally.
- The public layer demonstrates real lifecycle semantics.
- The private layer has a clear reason to exist.
- Commercial value comes from secure provider execution and operational reliability, not merely from withholding the concept.

### Security

- Plaintext exposure is minimized in the public architecture.
- Trust boundaries are documented.
- The system does not make impossible operator-access claims.
- Failed renewals produce visible, auditable outcomes.

## Suggested MVP milestones

### Milestone 1 — Protocol and domain model

- Define lifecycle states and valid transitions.
- Define identity, provider binding, ownership, policy, rotation-run, and event schemas.
- Define protocol versioning and conformance rules.

### Milestone 2 — Open control-plane shell

- Implement minimal persistence and APIs.
- Add lifecycle transition validation.
- Add audit event recording.
- Add a local/simulated provider adapter.

### Milestone 3 — Public frontend

- Identity inventory.
- Ownership view.
- Expiry/renewal dashboard.
- Rotation-run detail.
- Lifecycle history and audit timeline.

### Milestone 4 — Azure boundary

- Define the private adapter contract.
- Connect the private Azure renewal implementation.
- Validate provider-state verification and failure handling.

### Milestone 5 — Vertical-slice validation

- Run a complete Azure flow from registration through renewal and retirement.
- Test failure and recovery paths.
- Validate the public/private repository boundary.
- Document the product demo and evaluator setup.
