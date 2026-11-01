# Enforcement

## Purpose

This note records how a tenant requires that sessions active in it are established through one of its own connections
(SSO-4.1 to SSO-4.6, SSO-9.3): the rule the package stores per tenant and the version that changes with every change;
the four contracts an application or `laravel-iam` binds (enforcement, inheritance, exemption and session revocation)
and their defaults; how the helper that changes the rule validates, asks for freshness, locks and revokes inside one
transaction; and the gate an adapter calls before refusing a session it could exempt.

## Invariants

- A tenant's rule is one row of `Models\TenantEnforcement` in `sso.enforcement.table` (`sso_enforcement`): its opaque
  `tenant_id`, fixed once the row exists, `tenant_hash` (`Enforcement\TenantHash`, the lower-case hex SHA-256 of the id)
  under a unique index, `enabled`, `connection_ids` (a JSON list, each id once, in id order), `version` and
  `changed_at`. A read goes by the hash and compares `tenant_id` byte for byte, so `acme`, `Acme` and `acme` with a
  trailing space never share a rule, whatever the column's collation. A tenant with no row is off. Tenant ids are 1 to
  255 bytes; an empty or overlong one is an `InvalidArgumentException`.
- `version` is a new lower-case ULID on every change, never reused. It is exposed on `Enforcement\EnforcementPolicy`, on
  `EnforcementSummary` and on `EnforcementChanged`, so an adapter records the version a session was checked against and
  rechecks a session whose version is stale (SSO-4.6). It is `null` only while a tenant never had a rule stored.
- Four contracts, each bound by the provider with a default that fails closed and kept when the application or a
  sibling bound it first:

  | Contract                           | Default                            | Binding   | Default behaviour                                                       |
  |------------------------------------|------------------------------------|-----------|-------------------------------------------------------------------------|
  | `Contracts\Enforcement`            | `Enforcement\DatabaseEnforcement`  | scoped    | Answers from the stored rule of the enforcing tenant                    |
  | `Contracts\EnforcementInheritance` | `Enforcement\OwnTenantInheritance` | singleton | Each tenant's own rule applies to it alone (SSO-4.2)                    |
  | `Contracts\EnforcementExemption`   | `Enforcement\NoExemptions`         | singleton | Nobody is exempt (SSO-4.4)                                              |
  | `Contracts\SessionRevocation`      | `Revocation\NoSessionRevocation`   | singleton | Revokes nothing and succeeds: existing sessions are untouched (SSO-4.5) |

- `DatabaseEnforcement::policy($tenantId, $application)` answers from current state on every call, never from a cache
  (SSO-4.6, SSO-11.2). While `sso.features.enforcement` is off it answers `notRequired($tenantId, $tenantId, null)`
  with no query and no other contract asked; a malformed switch fails closed (`InvalidArgumentException`). Otherwise it
  asks the inheritance contract, resolved from the container on each call, for the enforcing tenant (an empty or
  overlong answer is a `LogicException`), reads that tenant's row through `Enforcement\EnforcementFinder` on the write
  connection, and answers `notRequired` with no row (version `null`) or a row that is off (its version), and
  `required` with a row that is on: satisfied by the stored connections that still exist, belong to the enforcing
  tenant byte for byte and are enabled, read in one statement. A rule whose every satisfying connection has since been
  disabled or deleted stays required and is satisfied by none; only an exemption admits a session then. An empty
  application is an `InvalidArgumentException`; a database error propagates (SSO-11.4), never read as not required.
- `Enforcement\EnforcementService` (`@api`, resolved per request) is the one helper that changes a rule. `get()` answers
  an `EnforcementSummary` from the write connection. `update($tenantId, $enabled, $connectionIds, $actor)` goes in a
  fixed order, and every refusal writes, revokes and reports nothing:
  1. the feature switch: off is `refused` with `feature_disabled`;
  2. the ids, validated as a whole: each a string of 1 to 26 bytes (`connection_ids.<n>` `invalid_type` or
     `invalid_format`, `<n>` its position in the list given), de-duplicated silently, at most
     `EnforcementService::MAX_CONNECTIONS` (50, `connection_ids` `too_many`), at least one while turning it on
     (`connection_ids` `required`), and each a connection of this tenant through `Connections\ConnectionFinder`
     (`connection_ids.<n>` `unknown`, the same for another tenant's connection as for an id with no connection, so no
     other tenant is revealed); any violation is `invalid` (`settings_invalid`) with every violation, in position order;
  3. the stored rule: the same switch and the same set of ids, in any order, is `unchanged`, with nothing asked;
  4. turning it on: one of the connections given must be enabled with `has_completed_sign_in` set, so a misconfigured
     connection cannot lock the tenant out (SSO-4.3), else `completed_sign_in_required`; turning it off needs none;
  5. freshness: `Freshness\FreshnessGate::check(FreshnessOperation::ENFORCEMENT_UPDATE)`, `sso.enforcement.update` with
     its configured maximum age (SSO-2.12); `stale` is `freshness_required`;
  6. one transaction on the storage connection (retried up to three times after a deadlock when it is the outermost):
     lock the tenant's row, then the connections given, steps 2 to 4 judged again on the locked rows, the write through
     the model (`enabled`, `connection_ids` sorted and unique, a new `version`, `changed_at` from the clock), the
     revocation when the rule is now on, and the report.
- Lock order: a tenant's enforcement row, then connection rows in id order (one locking statement by id, ordered by
  id, with the tenant compared byte for byte in PHP). Every read under the lock that decides the write is a locking
  read, since a plain read answers from the snapshot of a transaction the caller opened (MySQL's `REPEATABLE READ`).
  BL-37's connection disable and delete take the same order: the tenant's enforcement row first when they touch it,
  then the connection, and call `SessionRevocation` with `RevocationScope::connection()` inside their transaction.
- A tenant's first row is created by an upsert keyed by `tenant_hash` that inserts the row off, with no connection and a
  placeholder version, or leaves an existing row as it is; the row is then read locked. A locking read of a row that
  does not exist would take a gap lock on MySQL, and racing first changes would deadlock on each other's gap locks; the
  upsert instead locks the existing row exclusively at once (`ON DUPLICATE KEY UPDATE`, `ON CONFLICT ... DO UPDATE`),
  so they queue on the row, inside a caller's transaction too. A row the change created and then refused is deleted
  before the transaction ends, so a refusal stores nothing.
- Revocation runs synchronously inside the change's transaction, after the write and before the report, whenever the
  rule is now on (turned on, or its set changed while on): `SessionRevocation::revoke(RevocationScope::tenant($policy))`
  with `$policy = EnforcementPolicy::required($tenantId, $tenantId, <the given connections that are enabled>,
  $version)`, the contract resolved from the container at that moment. Turning it off revokes nothing. An adapter
  writes through the same Laravel connection as the package (decision D5), so its writes commit or roll back with the
  change; one that writes through another connection is not atomic with it. An exception from the revocation rolls
  the whole change back (no row, no new version, no event) and propagates as a server error.
- Each change is reported once, inside its transaction, through `Administration\EnforcementEvents::changed()`
  (`EnforcementChanged`, with the tenant, the acting identity, `enabled`, `connectionIds`, `version` and
  `previousVersion`, `null` for a tenant's first row), dispatched after commit and never when it rolls back (SSO-10.5).
  The event only reports: security never depends on a listener (SSO-9.3).
- `Enforcement\ExemptionGate::admit($policy, $application, $identity, $sessionId)` (`@api`) is what an adapter calls
  when a session in an enforcing tenant would otherwise be refused (SSO-4.4, SSO-9.3). A policy that requires nothing
  answers `not_exempt` with nothing asked or reported. Otherwise it asks `EnforcementExemption`, resolved from the
  container on each call; `exempt` is reported once through `EnforcementEvents::exemptionUsed()` (`ExemptionUsed`, after
  the storage connection's open transaction commits, at once when none is open) and returned. An exception from the
  contract propagates: the gate never answers `exempt` when it cannot tell.
- Every outcome of a change is an `Enforcement\EnforcementResult` (status `Enforcement\Enums\EnforcementStatus`):
  `updated` or `unchanged` with an `EnforcementSummary`; `refused` with `feature_disabled`, `freshness_required` or
  `completed_sign_in_required`; `invalid` with `settings_invalid` and its `Connections\SettingViolation`s. A violation
  names a position and a code, never an id.

## Success Path

1. An administrator enables a connection and signs in through it once, which sets `has_completed_sign_in`.
2. The administration screen calls `update($tenantId, true, [$connectionId], $actor)`: the id is the tenant's, the
   connection has completed a sign-in, freshness answers `fresh`, and in one transaction the row is written with a new
   version, the revocation removes the sessions the rule no longer allows, and `EnforcementChanged` is queued.
3. The transaction commits; the change and the revocation become visible together, and the event reaches listeners.
4. From the next call, `Contracts\Enforcement` answers `required` with the connection and the new version; under
   `laravel-iam` the tenant authentication policy (AUTH-2.12) refuses a session not established through it, unless the
   adapter's call to `ExemptionGate::admit()` answers `exempt`.

## Failure / Edge Cases

- The feature off: `policy()` requires nothing and reads nothing; `update()` is `feature_disabled`; `get()` still reads.
- A connection disabled or deleted after `update()` first read it is seen by the locking read in the transaction:
  `completed_sign_in_required` or `unknown`, with nothing stored. A change another process made identical meanwhile is
  `unchanged` under the lock, and reports nothing.
- Racing changes of one tenant serialise on its row: one first change stores the row and the rest are `unchanged`, and
  changes to different sets form one chain of versions, each replacing the one committed before it.
- A revocation that throws, a database error, an exemption contract that throws and an inheritance contract that throws
  all propagate (SSO-11.4). Inside the application's own transaction, a deadlock propagates rather than being retried.
- A rule left with no enabled connection stays on and admits nobody but the exempt; turning it off, or naming an
  enabled connection, is the way out.

## Implementation Anchors

- `src/Enforcement/DatabaseEnforcement.php`, `EnforcementFinder.php`, `EnforcementService.php`, `EnforcementResult.php`,
  `EnforcementSummary.php`, `ExemptionGate.php`, `Enums/EnforcementStatus.php`; `EnforcementPolicy.php`,
  `TenantHash.php`, `OwnTenantInheritance.php`, `NoExemptions.php`, `Enums/ExemptionOutcome.php`.
- `src/Contracts/Enforcement.php`, `EnforcementInheritance.php`, `EnforcementExemption.php`, `SessionRevocation.php`;
  `src/Revocation/RevocationScope.php`, `NoSessionRevocation.php`, `Enums/`.
- `src/Models/TenantEnforcement.php`, `database/migrations/2026_11_02_000001_create_sso_enforcement_table.php`.
- `src/Administration/EnforcementEvents.php`; `src/Events/EnforcementChanged.php`, `ExemptionUsed.php`.

## Authoritative Tests

- `tests/Feature/Enforcement/DatabaseEnforcementTest.php`, `EnforcementServiceTest.php`, `ExemptionGateTest.php`.
- `tests/Unit/Enforcement/EnforcementResultTest.php`, `EnforcementSummaryTest.php`, `EnforcementPolicyTest.php`,
  `EnforcementDefaultsTest.php`; `tests/Unit/Revocation/RevocationScopeTest.php`.
- `tests/Integration/Enforcement/EnforcementRevocationTransactionTest.php`, `ConcurrentEnforcementChangesTest.php`
  (MySQL and PostgreSQL, plainly and inside a caller's transaction), `EnforcementMigrationTest.php`.
- `tests/Performance/EnforcementQueryBudgetTest.php`.

## Change Triggers

- A change to what `policy()` answers, to when it reads, or to the feature switch's effect.
- A change to the validation, the order of a change, the completed sign-in rule or the freshness operation.
- A change to the lock order, the first-row upsert, or where the revocation is called; any new caller of
  `SessionRevocation` (BL-31's link removal, BL-37's connection lifecycle).
- A new outcome or reason of `EnforcementResult`, or a change to the exemption gate.
