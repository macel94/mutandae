# Open-core boundary

## Purpose

The repository should be open enough to build trust and demonstrate real value while preserving the provider-specific execution and operational expertise that differentiates the managed product.

## Public layer

The public layer includes:

- frontend application;
- cloud-agnostic lifecycle concepts;
- shared lifecycle and rotation protocol;
- public schemas and abstractions;
- state-machine and transition rules;
- audit/event contracts;
- minimal backend/control-plane shell;
- credential-less simulators and standard-library real adapters for Azure/Entra,
  AWS IAM, and GCP IAM;
- the consuming-side adapter and optional vault boundaries;
- examples, fixtures, and conformance tests;
- architecture and security documentation.

## Commercial layer

The open release includes real provider clients, but a managed or commercial
offering may add:

- secure managed execution and deployment-specific credential delivery;
- provider-specific operational safeguards, retries, edge cases, and recovery
  maintained as a service;
- broader provider and identity-class coverage;
- advanced enterprise integrations;
- managed operations, availability, and reliability tooling.

These are commercial operating and maintenance capabilities, not a claim that
basic provider mechanics are absent from the public source.

## Boundary rules

1. Public interfaces describe **what** lifecycle operation is requested and **what** result is expected.
2. Public adapters implement **how** a provider-specific operation is executed;
   commercial deployments may add further execution policy and operations.
3. Public code must not contain production provider credentials or hidden service endpoints.
4. Public protocol schemas must not encode private implementation details.
5. The frontend consumes control-plane contracts, not provider SDKs directly.
6. Provider-specific identifiers may appear in public abstractions where needed;
   deployment-specific credentials, policy, and operational safeguards remain
   outside the source tree.
7. The public simulator must model meaningful success and failure states rather than pretending to be production execution.
8. Security documentation must state what is and is not protected by the open layer.

## Why this split is defensible

The generalized lifecycle model—TTL, renewal, rotation, revocation, and audit—is already an established pattern. Sharing that model creates credibility and interoperability.

The commercial moat is the difficult operational layer:

- safe renewal across provider APIs;
- tenant/account/project edge cases;
- credential delivery without unnecessary exposure;
- reliable retries and rollback-aware workflows;
- execution in real customer environments;
- and the expertise required to operate this securely.

## What must remain true

The open-source project must be genuinely useful without being the entire managed service. A developer should be able to:

- understand the protocol;
- run the control-plane shell;
- simulate lifecycle changes;
- inspect ownership and audit workflows;
- build a compatible adapter;
- and evaluate the product thesis.

A paying customer should receive more than source-code access:

- production-grade execution;
- provider coverage and maintenance;
- secure operations;
- reliability guarantees appropriate to the service;
- and reduced operational burden.
