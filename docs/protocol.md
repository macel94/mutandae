# μTandae Protocol Specification

## 1. Purpose and versioning

The μTandae Protocol is a versioned, provider-neutral JSON wire contract for
machine-identity lifecycle governance. It is used across the cloud-provider
adapter, control plane, and frontend/API consumer boundaries. The protocol owns
lifecycle semantics, audit correlation, message envelopes, and conformance
rules; it does not encode provider-specific renewal mechanics or secret
material.

The current protocol constants are:

| Identifier | Value | Use |
| --- | --- | --- |
| `Version` | `v1` | Current protocol version. Consumers should negotiate this through the `api_version` field in a discovery index and on response envelopes rather than hard-coding a string. |
| `MediaType` | `application/vnd.mutandae.v1+json` | Versioned JSON representation of the protocol. |
| `ContentType` | `application/vnd.mutandae.v1+json; charset=utf-8` | Content type emitted for protocol responses and accepted by conformance clients. |
| `Accept` | `application/vnd.mutandae.v1+json` | Media type clients use to name the supported protocol version; servers should reject an unsupported version. |

JSON field names in this document are the names supplied by the Go `json`
tags. A field marked `omitempty` is optional in the representation. A field
without `omitempty` is emitted by the Go type's JSON representation even when
its Go value is the zero value. These wire-level tags are distinct from the
semantic requirements enforced by `ValidateIdentity`, `ValidateEvent`, and
`ValidateRotationRun` (see [Conformance rules](#8-conformance-rules)).

Every response envelope defined below has an `api_version` field. The request
structs in this version do not define an `api_version` field. A conforming
response uses `v1`; `Failure` constructs an `ErrorResponse` with
`api_version: "v1"`.

## 2. Core object schemas

### 2.1 `MachineIdentity`

`MachineIdentity` is the controlled, versioned representation of a governed
non-human identity. `ProviderBinding`, `Ownership`, `LifecyclePolicy`, and
`CredentialReference` are value objects embedded in it.

| Go field | JSON field | Go type | Wire presence / conformance |
| --- | --- | --- | --- |
| `ID` | `id` | `string` | Required by `ValidateIdentity`. |
| `Name` | `name` | `string` | Required by `ValidateIdentity`. |
| `DisplayName` | `display_name` | `string` | Optional (`omitempty`). |
| `Namespace` | `namespace` | `string` | Optional (`omitempty`). |
| `Environment` | `environment` | `string` | Optional (`omitempty`). |
| `Provider` | `provider` | `ProviderBinding` | Optional tag (`omitempty`); `provider.provider` and `provider.provider_id` are required by `ValidateIdentity`. |
| `Ownership` | `ownership` | `Ownership` | Optional tag (`omitempty`); `ownership.team`, `ownership.service`, and `ownership.purpose` are required by `ValidateIdentity`. |
| `Policy` | `policy` | `LifecyclePolicy` | Optional tag (`omitempty`). `policy.renewal_period`, when non-empty, must parse as a supported ISO-8601 duration under `ValidateIdentity`. |
| `Credential` | `credential` | `CredentialReference` | Optional (`omitempty`). It should not contain secret material. |
| `State` | `state` | `State` | Required by the JSON tag and must be a valid `State` value. |
| `Health` | `health` | `Health` | Required by the JSON tag and must be a valid `Health` value. |
| `ExpiresAt` | `expires_at` | `time.Time` | Required by the JSON tag; `ValidateIdentity` does not require it to be non-zero. |
| `LastRotatedAt` | `last_rotated_at` | `time.Time` | Optional (`omitempty`). |
| `CreatedAt` | `created_at` | `time.Time` | Optional (`omitempty`). |
| `UpdatedAt` | `updated_at` | `time.Time` | Optional (`omitempty`). |
| `Metadata` | `metadata` | `Metadata` | Optional (`omitempty`). |

Example:

```json
{
  "id": "mi-orders-worker-001",
  "name": "orders-worker",
  "display_name": "Orders worker",
  "namespace": "production",
  "environment": "prod",
  "provider": {
    "provider": "azure-entra",
    "provider_id": "managed-identity-001",
    "tenant_id": "tenant-001",
    "object_id": "object-001",
    "region": "westeurope",
    "account_id": "account-001",
    "project_id": "project-001"
  },
  "ownership": {
    "team": "orders",
    "service": "order-api",
    "purpose": "Process orders",
    "criticality": "high",
    "contacts": ["#orders", "orders@example.invalid"]
  },
  "policy": {
    "renewal_period": "P90D",
    "grace_period": "P14D",
    "max_age": "P365D",
    "approval_required": true
  },
  "credential": {
    "kind": "x509_thumbprint",
    "location": "credential-reference-001",
    "fingerprint": "fingerprint-001",
    "key_id": "key-001",
    "delivery": "keyvault-ref"
  },
  "state": "active",
  "health": "healthy",
  "expires_at": "2026-01-15T00:00:00Z",
  "last_rotated_at": "2025-10-15T00:00:00Z",
  "created_at": "2025-01-15T00:00:00Z",
  "updated_at": "2025-10-15T00:00:00Z",
  "metadata": {
    "cost_center": "cc-001",
    "owner_system": "orders"
  }
}
```

### 2.2 `ProviderBinding`

`ProviderBinding` identifies an identity in a provider's domain. Its contents
are opaque to the control plane; the provider chooses the meaning of the
provider-specific identifier fields.

| Go field | JSON field | Go type | Wire presence |
| --- | --- | --- | --- |
| `Provider` | `provider` | `string` | Required (no `omitempty`). Example provider names in the source comments include `azure-entra`, `aws-iam`, and `gcp-iam`. |
| `ProviderID` | `provider_id` | `string` | Required (no `omitempty`). |
| `TenantID` | `tenant_id` | `string` | Optional (`omitempty`). |
| `ObjectID` | `object_id` | `string` | Optional (`omitempty`). |
| `Region` | `region` | `string` | Optional (`omitempty`). |
| `AccountID` | `account_id` | `string` | Optional (`omitempty`). |
| `ProjectID` | `project_id` | `string` | Optional (`omitempty`). |

Example:

```json
{
  "provider": "azure-entra",
  "provider_id": "managed-identity-001",
  "tenant_id": "tenant-001",
  "object_id": "object-001",
  "region": "westeurope",
  "account_id": "account-001",
  "project_id": "project-001"
}
```

### 2.3 `Ownership`

`Ownership` records who is accountable, which service is involved, and the
purpose of the identity. Contacts are opaque display, Slack, or email handles.

| Go field | JSON field | Go type | Wire presence |
| --- | --- | --- | --- |
| `Team` | `team` | `string` | Required (no `omitempty`); required by `ValidateIdentity` when embedded in an identity. |
| `Service` | `service` | `string` | Required (no `omitempty`); required by `ValidateIdentity` when embedded in an identity. |
| `Purpose` | `purpose` | `string` | Required (no `omitempty`); required by `ValidateIdentity` when embedded in an identity. |
| `Criticality` | `criticality` | `string` | Required (no `omitempty`); no value set or validation rule is defined by this package. |
| `Contacts` | `contacts` | `[]string` | Optional (`omitempty`). |

Example:

```json
{
  "team": "orders",
  "service": "order-api",
  "purpose": "Process orders",
  "criticality": "high",
  "contacts": ["#orders", "orders@example.invalid"]
}
```

### 2.4 `LifecyclePolicy`

`LifecyclePolicy` is the machine-readable renewal and governance policy.
`RenewalPeriod`, `GracePeriod`, and `MaxAge` are represented as ISO-8601
duration strings when supplied. The conformance validator only parses a
non-empty `renewal_period`.

| Go field | JSON field | Go type | Wire presence / conformance |
| --- | --- | --- | --- |
| `RenewalPeriod` | `renewal_period` | `string` | Required by the JSON tag, but not required to be non-empty by `ValidateIdentity`; if non-empty, it must parse with `ParseISO8601Duration`. |
| `GracePeriod` | `grace_period` | `string` | Optional (`omitempty`); not parsed by `ValidateIdentity`. |
| `MaxAge` | `max_age` | `string` | Optional (`omitempty`); not parsed by `ValidateIdentity`. |
| `ApprovalRequired` | `approval_required` | `bool` | Required by the JSON tag. |

Example:

```json
{
  "renewal_period": "P90D",
  "grace_period": "P14D",
  "max_age": "P365D",
  "approval_required": true
}
```

### 2.5 `CredentialReference`

`CredentialReference` describes where related credential material lives and how
to verify it. It is a reference, not a secret store, and should never carry
secret material.

| Go field | JSON field | Go type | Wire presence |
| --- | --- | --- | --- |
| `Kind` | `kind` | `string` | Required (no `omitempty`). Example kinds in the source comments include `client_secret`, `x509_thumbprint`, and `access_key`. |
| `Location` | `location` | `string` | Required (no `omitempty`); this is a provider reference, not a secret. |
| `Fingerprint` | `fingerprint` | `string` | Optional (`omitempty`). |
| `KeyID` | `key_id` | `string` | Optional (`omitempty`). |
| `Delivery` | `delivery` | `string` | Optional (`omitempty`). Example delivery values in the source comments include `keyvault-ref`, `environment`, and `secret-manager`. |

Example:

```json
{
  "kind": "x509_thumbprint",
  "location": "credential-reference-001",
  "fingerprint": "fingerprint-001",
  "key_id": "key-001",
  "delivery": "keyvault-ref"
}
```

### 2.6 `LifecycleEvent`

`LifecycleEvent` is an immutable audit-correlation record. Its `type` uses the
dotted event taxonomy in [Event taxonomy](#4-event-taxonomy), and its `outcome`
uses the `Outcome` enumeration.

| Go field | JSON field | Go type | Wire presence / conformance |
| --- | --- | --- | --- |
| `ID` | `id` | `string` | Required by `ValidateEvent`. |
| `IdentityID` | `identity_id` | `string` | Required by `ValidateEvent`. |
| `Type` | `type` | `EventType` | Required by `ValidateEvent` only as non-empty; the validator does not require one of the declared event constants. |
| `Summary` | `summary` | `string` | Required by `ValidateEvent`. |
| `Actor` | `actor` | `string` | Required by `ValidateEvent` only as non-empty; adapters may supply provider-scoped actor identifiers. |
| `Outcome` | `outcome` | `Outcome` | Required by `ValidateEvent` and must be a valid `Outcome` value. |
| `At` | `at` | `time.Time` | Required by `ValidateEvent` as a non-zero time. |
| `CorrelationID` | `correlation_id` | `string` | Optional (`omitempty`). |
| `RunID` | `run_id` | `string` | Optional (`omitempty`). |
| `Details` | `details` | `map[string]string` | Optional (`omitempty`). |

Example:

```json
{
  "id": "event-001",
  "identity_id": "mi-orders-worker-001",
  "type": "identity.registered",
  "summary": "Machine identity registered",
  "actor": "control-plane",
  "outcome": "success",
  "at": "2025-01-15T00:00:00Z",
  "correlation_id": "correlation-001",
  "run_id": "run-001",
  "details": {
    "source": "discovery"
  }
}
```

### 2.7 `RotationRun`

`RotationRun` records a planned or executed renewal/rotation workflow. A control
plane tracks it from requested to started to terminal, attaching provider
evidence when it becomes available.

| Go field | JSON field | Go type | Wire presence / conformance |
| --- | --- | --- | --- |
| `ID` | `id` | `string` | Required by `ValidateRotationRun`. |
| `IdentityID` | `identity_id` | `string` | Required by `ValidateRotationRun`. |
| `Status` | `status` | `RotationStatus` | Required by `ValidateRotationRun` and must be a valid `RotationStatus` value. |
| `RequestedBy` | `requested_by` | `string` | Optional (`omitempty`). |
| `RequestedAt` | `requested_at` | `time.Time` | Optional (`omitempty`). |
| `StartedAt` | `started_at` | `time.Time` | Optional (`omitempty`). |
| `FinishedAt` | `finished_at` | `time.Time` | Optional (`omitempty`). |
| `Outcome` | `outcome` | `Outcome` | Optional (`omitempty`); no outcome requirement is enforced by `ValidateRotationRun`. |
| `Evidence` | `evidence` | `CredentialReference` | Optional (`omitempty`). |
| `Error` | `error` | `string` | Optional (`omitempty`). |

Example:

```json
{
  "id": "run-001",
  "identity_id": "mi-orders-worker-001",
  "status": "succeeded",
  "requested_by": "operator",
  "requested_at": "2025-10-15T00:00:00Z",
  "started_at": "2025-10-15T00:01:00Z",
  "finished_at": "2025-10-15T00:03:00Z",
  "outcome": "success",
  "evidence": {
    "kind": "x509_thumbprint",
    "location": "credential-reference-002",
    "fingerprint": "fingerprint-002",
    "key_id": "key-002",
    "delivery": "keyvault-ref"
  }
}
```

### 2.8 `Metadata`

`Metadata` is a named type for a `map[string]string`. It reserves a
provider- or deployment-specific key/value extension point without changing
the versioned core schema.

Example:

```json
{
  "cost_center": "cc-001",
  "owner_system": "orders"
}
```

## 3. Enumeration values

Consumers must use the exact string values below. The `Valid*` helpers reject
values outside their corresponding table.

### `State`

| Go constant | JSON/string value |
| --- | --- |
| `StateRegistered` | `registered` |
| `StateActive` | `active` |
| `StateRenewing` | `renewing` |
| `StateRetired` | `retired` |

### `Health`

| Go constant | JSON/string value |
| --- | --- |
| `HealthHealthy` | `healthy` |
| `HealthAttention` | `attention` |

### `Urgency`

| Go constant | JSON/string value |
| --- | --- |
| `UrgencyHealthy` | `healthy` |
| `UrgencyExpiring` | `expiring` |
| `UrgencyOverdue` | `overdue` |
| `UrgencyRetired` | `retired` |

`Urgency` is a derived, time-boxed advisory signal normally computed by the
control plane from state and expiry. It is a distinct type even where its
string value overlaps another enumeration.

### `RotationStatus`

| Go constant | JSON/string value |
| --- | --- |
| `RotationPending` | `pending` |
| `RotationRunning` | `running` |
| `RotationSucceeded` | `succeeded` |
| `RotationFailed` | `failed` |
| `RotationRollBack` | `rolled_back` |

### `Outcome`

| Go constant | JSON/string value |
| --- | --- |
| `OutcomeSuccess` | `success` |
| `OutcomeInProgress` | `in_progress` |
| `OutcomeAttention` | `attention` |
| `OutcomeFailure` | `failure` |
| `OutcomeCancelled` | `cancelled` |

### `ErrorCode`

`ErrorCode` is the stable, machine-readable classification carried on an
`ErrorResponse` and surfaced by adapter errors. `Message` is human-readable;
`Details`, when present, carries structured string context.

| Go constant | JSON/string value |
| --- | --- |
| `ErrCodeInvalidRequest` | `invalid_request` |
| `ErrCodeConformanceFailure` | `conformance_failure` |
| `ErrCodeNotFound` | `not_found` |
| `ErrCodeInvalidTransition` | `invalid_transition` |
| `ErrCodeAlreadyRetired` | `already_retired` |
| `ErrCodeRotationInProgress` | `rotation_in_progress` |
| `ErrCodeProviderFailure` | `provider_failure` |
| `ErrCodeUnsupportedVersion` | `unsupported_version` |
| `ErrCodeConflict` | `conflict` |
| `ErrCodeInternal` | `internal` |
| `ErrCodeUnimplemented` | `unimplemented` |

## 4. Event taxonomy

`EventType` values use the dotted `<domain>.<verb>` namespace. Consumers should
preserve the exact type string when correlating identity, rotation-run, and
actor records.

| Go constant | Event type string | Category |
| --- | --- | --- |
| `EventIdentityDiscovered` | `identity.discovered` | Discovery, registration, and ownership |
| `EventIdentityRegistered` | `identity.registered` | Discovery, registration, and ownership |
| `EventIdentityImported` | `identity.imported` | Discovery, registration, and ownership |
| `EventOwnershipAssigned` | `ownership.assigned` | Discovery, registration, and ownership |
| `EventOwnershipChanged` | `ownership.changed` | Discovery, registration, and ownership |
| `EventPolicyApplied` | `policy.applied` | Policy and renewal health |
| `EventRenewalAlerted` | `renewal.alerted` | Policy and renewal health |
| `EventExpiryImminent` | `expiry.imminent` | Policy and renewal health |
| `EventExpiryOverdue` | `expiry.overdue` | Policy and renewal health |
| `EventRotationRequested` | `rotation.requested` | Rotation workflow |
| `EventRotationStarted` | `rotation.started` | Rotation workflow |
| `EventRotationCompleted` | `rotation.completed` | Rotation workflow |
| `EventRotationFailed` | `rotation.failed` | Rotation workflow |
| `EventRotationRollBack` | `rotation.rolled_back` | Rotation workflow |
| `EventIdentityRetired` | `identity.retired` | Decommissioning |
| `EventIdentityRevoked` | `identity.revoked` | Decommissioning |
| `EventIdentityResurrected` | `identity.resurrected` | Decommissioning |

A rotation should emit exactly one `rotation.started` event followed by exactly
one terminal event: `rotation.completed` or `rotation.failed`. The taxonomy
also includes `rotation.rolled_back` for rollback events.

The actor constants are untyped string constants and are used as the following
actor names:

| Go constant | Actor string |
| --- | --- |
| `ActorOperator` | `operator` |
| `ActorControlPlane` | `control-plane` |
| `ActorProviderAdapter` | `provider-adapter` |
| `ActorDiscovery` | `discovery` |

Adapters may supply provider-scoped actor identifiers in addition to these
control-plane actor names.

## 5. ISO-8601 duration rules

The protocol represents renewal, grace, and maximum-age periods as duration
strings rather than Go `time.Duration` values. The helpers are
`ParseISO8601Duration` and `FormatISO8601Duration`.

### Parsing with `ParseISO8601Duration`

The documented supported forms are:

- `P{n}D` — a number of days;
- `P{n}W` — a number of weeks;
- `PT{n}H` — a number of hours;
- `PT{n}M` — a number of minutes; and
- `PT{n}S` — a number of seconds.

The forms can be combined, for example `P1DT6H`. The parser trims leading and
trailing whitespace, requires the uppercase `P` designator, and requires at
least one duration component. The time designator `T` must precede hours,
minutes, and seconds in the supported forms. `M` before `T` is treated as a
calendar-month position and is rejected because months are unsupported. Years
(`Y`) and calendar months are not supported. The parser is case-sensitive, so
`PT6H` is supported while `PT6h` is not.

Numeric components are converted to `time.Duration`. The source contract
specifically documents decimal seconds to millisecond precision; the current
implementation parses the numeric token as floating point for every supported
unit and does not explicitly reject additional fractional digits. The resulting
conversion is still limited by `time.Duration`, and the formatter emits only
milliseconds. The implementation recognizes `D`, `W`, `H`, `M`, and `S` units;
`D` and `W` are converted to fixed 24-hour and seven-day periods rather than
calendar units. It applies positional checks for the time designator, but does
not enforce canonical component ordering or uniqueness, so repeated or
non-canonical components that pass those checks are accumulated. Malformed
numbers, missing values, trailing values, unexpected characters, and units in an
invalid position return an error.

### Formatting with `FormatISO8601Duration`

`FormatISO8601Duration` produces a compact representation by decomposing a
positive duration into days followed by sub-day time components in this order:

1. days (`D`),
2. hours (`H`),
3. minutes (`M`),
4. whole seconds and milliseconds (`S`).

Zero-value components are omitted. A time designator is written only when at
least one sub-day component is present. Non-positive durations, including zero,
format as `P0D`. Representative outputs from the implementation are:

| Input shape | Output |
| --- | --- |
| 90 whole days | `P90D` |
| 6 hours | `PT6H` |
| 1 day and 6 hours | `P1DT6H` |
| 6 minutes and 30 seconds | `PT6M30S` |
| 125 milliseconds | `PT0.125S` |

The formatter emits at most millisecond precision and drops any sub-millisecond
remainder. Consequently, a positive duration smaller than one millisecond is
formatted as `P` by the current implementation, and that string is not accepted
by `ParseISO8601Duration`; callers should use durations at millisecond precision
or greater. Likewise, a positive duration with a sub-millisecond remainder
loses that remainder in the formatted representation.

## 6. Canonical lifecycle state machine

`AllowedTransitions` is the canonical versioned state machine:

```go
var AllowedTransitions = map[State]map[State]bool{
    StateRegistered: {
        StateActive: true,
    },
    StateActive: {
        StateRenewing: true,
        StateRetired:  true,
    },
    StateRenewing: {
        StateActive:  true,
        StateRetired: true,
    },
    StateRetired: {},
}
```

The short transition diagram is:

```text
registered -> active -> renewing -> active
                  |              |
                  v              v
               retired        retired
```

The arrows above are the only allowed transitions. In particular, a renewal
may be aborted by transitioning from `renewing` to `retired`.

`CanTransition(from, to)` looks up `from` in `AllowedTransitions`. It returns
the boolean value stored for `to`; a missing source state or missing target
returns `false`. It never panics, and unknown states are invalid. There are no
implicit self-transitions, and `retired` has no outgoing transitions.

The complete pairwise transition table is:

| From | To | Allowed |
| --- | --- | --- |
| `registered` | `registered` | No |
| `registered` | `active` | Yes |
| `registered` | `renewing` | No |
| `registered` | `retired` | No |
| `active` | `registered` | No |
| `active` | `active` | No |
| `active` | `renewing` | Yes |
| `active` | `retired` | Yes |
| `renewing` | `registered` | No |
| `renewing` | `active` | Yes |
| `renewing` | `renewing` | No |
| `renewing` | `retired` | Yes |
| `retired` | `registered` | No |
| `retired` | `active` | No |
| `retired` | `renewing` | No |
| `retired` | `retired` | No |

`KnownStates()` returns the canonical states in declaration order:
`registered`, `active`, `renewing`, `retired`.

## 7. Message envelopes

The message types are JSON documents exchanged on the control-plane API and
between the control plane and provider adapters. Fields marked required below
have no `omitempty` tag in the corresponding Go struct, unless the table also
calls out an operation-level semantic requirement. Optional fields have
`omitempty`.

### 7.1 Discovery

#### `DiscoveryResource`

A discovery resource advertises one related protocol resource. The documented
relation values are `identity`, `list`, `register`, `inspect`, `rotate`, and
`retire`.

| Go field | JSON field | Go type | Required |
| --- | --- | --- | --- |
| `Rel` | `rel` | `string` | Yes |
| `Method` | `method` | `string` | Yes |
| `HREF` | `href` | `string` | Yes |
| `Envelope` | `envelope` | `string` | No (`omitempty`) |

#### `DiscoveryIndex`

The discovery index is returned by the protocol root and advertises the
versioned resources a consumer may use.

| Go field | JSON field | Go type | Required |
| --- | --- | --- | --- |
| `APIVersion` | `api_version` | `string` | Yes |
| `Service` | `service` | `string` | Yes |
| `MediaType` | `media_type` | `string` | Yes |
| `Resources` | `resources` | `[]DiscoveryResource` | Yes |
| `Error` | `error` | `*Error` | No (`omitempty`) |

### 7.2 List

#### `ListRequest`

`ListRequest` filters the identity inventory. Every filter is optional.

| Go field | JSON field | Go type | Required |
| --- | --- | --- | --- |
| `Provider` | `provider` | `string` | No (`omitempty`) |
| `Environment` | `environment` | `string` | No (`omitempty`) |
| `State` | `state` | `State` | No (`omitempty`) |
| `Limit` | `limit` | `int` | No (`omitempty`) |
| `After` | `after` | `string` | No (`omitempty`) |
| `Namespaces` | `namespaces` | `[]string` | No (`omitempty`) |

#### `ListResponse`

`ListResponse` returns a conformant inventory.

| Go field | JSON field | Go type | Required |
| --- | --- | --- | --- |
| `APIVersion` | `api_version` | `string` | Yes |
| `Total` | `total` | `int` | Yes |
| `Identities` | `identities` | `[]MachineIdentity` | Yes |
| `Omitted` | `omitted` | `int` | No (`omitempty`); greater than zero means the list was truncated. |
| `Error` | `error` | `*Error` | No (`omitempty`) |

### 7.3 Inspect

#### `InspectRequest`

`InspectRequest` fetches one identity by control-plane ID.

| Go field | JSON field | Go type | Required |
| --- | --- | --- | --- |
| `ID` | `id` | `string` | Yes |

#### `InspectResponse`

`InspectResponse` returns one conformant identity.

| Go field | JSON field | Go type | Required |
| --- | --- | --- | --- |
| `APIVersion` | `api_version` | `string` | Yes |
| `Identity` | `identity` | `MachineIdentity` | Yes |
| `Error` | `error` | `*Error` | No (`omitempty`) |

### 7.4 Register

#### `RegisterRequest`

`RegisterRequest` provisions or imports a new machine identity. The provider
binding is required; the control plane assigns `id` unless the caller supplies
one.

| Go field | JSON field | Go type | Required |
| --- | --- | --- | --- |
| `ID` | `id` | `string` | No (`omitempty`); assigned by the control plane when absent. |
| `Name` | `name` | `string` | Yes |
| `DisplayName` | `display_name` | `string` | No (`omitempty`) |
| `Namespace` | `namespace` | `string` | No (`omitempty`) |
| `Environment` | `environment` | `string` | No (`omitempty`) |
| `Provider` | `provider` | `ProviderBinding` | Yes |
| `Ownership` | `ownership` | `Ownership` | Yes |
| `Policy` | `policy` | `LifecyclePolicy` | Yes |
| `Credential` | `credential` | `CredentialReference` | No (`omitempty`) |
| `ExpiresAt` | `expires_at` | `time.Time` | No (`omitempty`) |
| `RequestedBy` | `requested_by` | `string` | No (`omitempty`) |

`RequestedByOrDefault()` returns `RequestedBy` when it is non-empty; otherwise
it returns the exact actor string `control-plane` (`ActorControlPlane`).

#### `RegisterResponse`

`RegisterResponse` returns the stored identity and the audit events produced by
registration.

| Go field | JSON field | Go type | Required |
| --- | --- | --- | --- |
| `APIVersion` | `api_version` | `string` | Yes |
| `Identity` | `identity` | `MachineIdentity` | Yes |
| `Events` | `events` | `[]LifecycleEvent` | No (`omitempty`) |
| `Error` | `error` | `*Error` | No (`omitempty`) |

### 7.5 Rotate

#### `RotateRequest`

`RotateRequest` starts a renewal or rotation for one machine identity.

| Go field | JSON field | Go type | Required |
| --- | --- | --- | --- |
| `ID` | `id` | `string` | Yes |
| `RequestedBy` | `requested_by` | `string` | No (`omitempty`) |
| `Reason` | `reason` | `string` | No (`omitempty`) |
| `Metadata` | `metadata` | `Metadata` | No (`omitempty`) |

`RequestedByOrDefault()` returns `RequestedBy` when it is non-empty; otherwise
it returns the exact actor string `operator` (`ActorOperator`).

#### `RotateResponse`

`RotateResponse` returns the post-rotation identity, its rotation run, and the
associated events.

| Go field | JSON field | Go type | Required |
| --- | --- | --- | --- |
| `APIVersion` | `api_version` | `string` | Yes |
| `Identity` | `identity` | `MachineIdentity` | Yes |
| `Rotation` | `rotation` | `RotationRun` | Yes |
| `Events` | `events` | `[]LifecycleEvent` | No (`omitempty`) |
| `Error` | `error` | `*Error` | No (`omitempty`) |

### 7.6 Retire

#### `RetireRequest`

`RetireRequest` decommissions a machine identity through an explicit lifecycle
transition. `confirm` is a required JSON field; `false` is not omitted.

| Go field | JSON field | Go type | Required |
| --- | --- | --- | --- |
| `ID` | `id` | `string` | Yes |
| `RequestedBy` | `requested_by` | `string` | No (`omitempty`) |
| `Reason` | `reason` | `string` | No (`omitempty`) |
| `Confirm` | `confirm` | `bool` | Yes |

`RequestedByOrDefault()` returns `RequestedBy` when it is non-empty; otherwise
it returns the exact actor string `operator` (`ActorOperator`).

#### `RetireResponse`

`RetireResponse` returns the post-retirement identity and its events.

| Go field | JSON field | Go type | Required |
| --- | --- | --- | --- |
| `APIVersion` | `api_version` | `string` | Yes |
| `Identity` | `identity` | `MachineIdentity` | Yes |
| `Events` | `events` | `[]LifecycleEvent` | No (`omitempty`) |
| `Error` | `error` | `*Error` | No (`omitempty`) |

### 7.7 Errors

#### `Error`

`Error` carries protocol error details. `code` is the stable classification and
`message` is human-readable. `details` can carry additional structured context
as string key/value pairs.

| Go field | JSON field | Go type | Required |
| --- | --- | --- | --- |
| `Code` | `code` | `ErrorCode` | Yes |
| `Message` | `message` | `string` | Yes |
| `Details` | `details` | `map[string]string` | No (`omitempty`) |

#### `ErrorResponse`

`ErrorResponse` is the canonical failure document.

| Go field | JSON field | Go type | Required |
| --- | --- | --- | --- |
| `APIVersion` | `api_version` | `string` | Yes |
| `Error` | `error` | `Error` | Yes |

`Failure(e Error)` returns an `ErrorResponse` with `api_version` set to
`Version` and `error` set to `e`. `NewError(code, message)` creates an `Error`
with the supplied `code` and `message`, leaving `details` unset.

## 8. Conformance rules

The package exposes the sentinel:

```text
ErrConformance = protocol: document does not conform to v1
```

All errors returned by the three validators unwrap to `ErrConformance`.
`ValidationErrors` collects multiple field failures and its `Unwrap()` method
returns `ErrConformance`, so callers can use wrapped-error matching against the
sentinel. A nil input returns a conformance error immediately:

- `ValidateIdentity(nil)`: `protocol: document does not conform to v1: identity is nil`
- `ValidateEvent(nil)`: `protocol: document does not conform to v1: event is nil`
- `ValidateRotationRun(nil)`: `protocol: document does not conform to v1: rotation run is nil`

For a non-nil document, validators collect all applicable failures and return
`nil` when there are none.

### `ValidateIdentity`

`ValidateIdentity` checks a `MachineIdentity` as follows:

- `id` is required (`id is required`).
- `name` is required (`name is required`).
- `provider.provider` is required (`provider.provider is required`).
- `provider.provider_id` is required (`provider.provider_id is required`).
- `ownership.team` is required (`ownership.team is required`).
- `ownership.service` is required (`ownership.service is required`).
- `ownership.purpose` is required (`ownership.purpose is required`).
- `state` must be one of the values accepted by `ValidState`; otherwise the
  error is `state %q is invalid`, with the supplied state inserted using Go's
  quoted-string formatting.
- `health` must be one of the values accepted by `ValidHealth`; otherwise the
  error is `health %q is invalid`, with the supplied health inserted using Go's
  quoted-string formatting.
- If `policy.renewal_period` is non-empty, it must be accepted by
  `ParseISO8601Duration`; otherwise the error is
  `policy.renewal_period is not a valid ISO-8601 duration`.

It does not require `expires_at`, `credential`, `policy.grace_period`,
`policy.max_age`, or a non-empty `policy.renewal_period`. It does not validate
`ownership.criticality`, `metadata`, provider-specific binding fields beyond
`provider` and `provider_id`, or timestamps beyond the listed fields.

### `ValidateEvent`

`ValidateEvent` checks these exact fields:

- `id` is required (`id is required`).
- `identity_id` is required (`identity_id is required`).
- `type` is required as a non-empty value (`type is required`).
- `summary` is required (`summary is required`).
- `actor` is required as a non-empty value (`actor is required`).
- `outcome` must be non-empty and accepted by `ValidOutcome`; otherwise the
  error is `outcome is invalid`.
- `at` is required as a non-zero `time.Time`; the check uses `v.At.UTC().IsZero()`
  and reports `at is required` when it is zero.

The validator does not require `type` to be one of the listed `EventType`
constants and does not require `actor` to be one of the listed actor constants.
It also does not validate optional correlation, run, or detail fields.

### `ValidateRotationRun`

`ValidateRotationRun` checks these exact fields:

- `id` is required (`id is required`).
- `identity_id` is required (`identity_id is required`).
- `status` must be non-empty and accepted by `ValidRotationStatus`; otherwise
  the error is `status is invalid`.

It does not require or validate `requested_by`, any run timestamps, `outcome`,
`evidence`, or `error`.

## 9. Public protocol and the open-core boundary

The public protocol deliberately contains provider-neutral semantics. A
provider may be identified through an opaque `ProviderBinding`, but provider-
specific execution—such as renewal mechanics, credential handling, provider
API calls, endpoints, or hostnames—stays behind the `ProviderAdapter` boundary.
The control plane, frontend, and other protocol consumers depend on this
contract rather than on cloud SDK details; provider-specific execution never
belongs in the protocol itself.
