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
- local or simulated provider adapter;
- examples, fixtures, and conformance tests;
- architecture and security documentation.

## Private layer

The private/commercial layer includes:

- production provider-specific renewal engines;
- Azure tenant-aware execution;
- future AWS and GCP renewal implementations;
- secure managed execution;
- credential material handling and delivery;
- provider-specific retries, edge cases, and recovery;
- advanced enterprise integrations;
- managed operations and reliability tooling.

## Boundary rules

1. Public interfaces describe **what** lifecycle operation is requested and **what** result is expected.
2. Private adapters implement **how** a provider-specific renewal is executed.
3. Public code must not contain production provider credentials or hidden service endpoints.
4. Public protocol schemas must not encode private implementation details.
5. The frontend consumes control-plane contracts, not provider SDKs directly.
6. Provider-specific identifiers may appear in public abstractions where needed, but private renewal algorithms and execution safeguards do not.
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
