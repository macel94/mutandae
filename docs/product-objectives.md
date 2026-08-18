# Product objectives

## Vision

Mutandae is an open-core control plane for machine identity lifecycle management across the major cloud ecosystems:

- Microsoft Entra ID / Azure
- AWS IAM
- GCP IAM

Its purpose is to provide a consistent way to provision, govern, renew, rotate, and retire non-human application identities and related credentials.

The long-term objective is to make machine identity governance as intentional and reliable as infrastructure lifecycle management.

## Problem

Organizations commonly face the same operational problems:

- machine identities are distributed across cloud providers;
- ownership is unclear or becomes stale;
- provider-specific identity models are difficult to compare;
- credential renewal is handled manually or inconsistently;
- expiry events become incidents;
- retirement is forgotten when applications or teams change;
- audit evidence is fragmented across cloud consoles and automation systems.

Mutandae exists to unify those realities behind a lifecycle and governance model that organizations can understand and operate.

## Product position

Mutandae is:

- a control plane for non-human identities;
- a lifecycle governance layer for application identities;
- a cross-cloud orchestration system for provisioning and renewal;
- a workflow and audit layer above provider-specific IAM primitives.

Mutandae is not:

- a generic secrets manager;
- a replacement for cloud IAM;
- a Vault clone;
- a broad human-IAM suite;
- a PAM replacement;
- a promise that operators can never access customer secrets.

## Core product objectives

### 1. Normalize the lifecycle

Define a common lifecycle vocabulary for:

- discovery and registration;
- provisioning;
- ownership assignment;
- activation;
- expiry tracking;
- scheduled renewal;
- rotation;
- revocation;
- decommissioning;
- audit correlation.

### 2. Make ownership operational

Every managed machine identity should have visible and actionable ownership metadata, including:

- owning team or service;
- responsible contacts;
- application/workload association;
- business purpose;
- provider and environment;
- criticality;
- renewal policy;
- retirement conditions.

### 3. Make change predictable

The system should show:

- what is changing;
- why it is changing;
- when it will change;
- which credentials or provider objects are affected;
- whether the change succeeded;
- what evidence was produced;
- and what recovery path exists if it fails.

### 4. Govern rather than merely store

Mutandae should prioritize lifecycle execution and governance over long-term plaintext storage. It should minimize secret exposure and integrate with existing secret-delivery systems where appropriate.

### 5. Keep the conceptual layer portable

The lifecycle protocol and control-plane abstractions should remain provider-neutral. Provider-specific adapters and renewal engines should translate those abstractions into Azure, AWS, and GCP mechanics.

### 6. Provide trustworthy auditability

Every important lifecycle action should be correlated to an auditable event with:

- identity and workload references;
- actor or automation source;
- provider and tenant/account/project context;
- timestamps;
- policy decision;
- outcome;
- failure details where applicable;
- and links to related rotation runs.

## Conceptual domain objects

The initial domain model should include:

- **MachineIdentity** — the governed non-human identity as a cross-provider concept.
- **ProviderBinding** — the provider-specific representation and identifiers.
- **CredentialMaterial** — a reference to related credentials without making Mutandae a universal secret store.
- **OwnershipRecord** — the accountable team, service, and contacts.
- **LifecyclePolicy** — expiry, renewal, rotation, approval, and retirement rules.
- **RotationRun** — a planned or executed renewal/rotation workflow.
- **LifecycleEvent** — an immutable audit correlation record.
- **ProviderAdapter** — a provider-aware implementation boundary.

## Security objectives

- Minimize plaintext credential exposure.
- Avoid unnecessary persistence of long-lived secret material.
- Make trust boundaries explicit.
- Separate public protocol concepts from private production execution.
- Fail safely when renewal cannot be verified.
- Support staged rotation and rollback-aware workflows.
- Never claim guarantees that the deployment model does not enforce.

## Long-term provider direction

The conceptual model should support all three major clouds, but implementation should proceed in stages:

1. Azure/Entra ID first.
2. AWS IAM second.
3. GCP IAM third.

Azure is the initial provider because its application-object/service-principal model provides a credible first vertical slice and matches the current product expertise.

## Product principles

- Lifecycle clarity over provider-console replication.
- Ownership as a first-class object.
- Provider-neutral concepts, provider-aware execution.
- Explicit renewal health.
- Safe change over broad storage.
- Auditability by design.
- Honest security claims.
- Narrow, excellent vertical slices over shallow multi-cloud breadth.
