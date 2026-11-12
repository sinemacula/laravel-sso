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
- A row whose `version` (and `changed_at`) is null is unconfigured: the guard row `Enforcement\EnforcementLock` inserts
  so a tenant that never had a rule still has a row to lock. It is semantically identical to no row:
  `EnforcementFinder::find()` answers none for it, `EnforcementSummary` is off with no connection, version or time,
  `policy()` requires nothing with version `null`, the writer judges it as no rule, and its first real change reports
  `previousVersion` `null`. It is never deleted, since another transaction may be waiting to lock it.
- `version` is a new lower-case ULID on every change, never reused. It is exposed on `Enforcement\EnforcementPolicy`, on
  `EnforcementSummary` and on `EnforcementChanged`, so an adapter records the version a session was checked against and
  rechecks a session whose version is stale (SSO-4.6). It is `null` only while a tenant never had a rule stored (no
  row, or only an unconfigured one).
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
  Its reads take no lock, so asked inside a transaction that has already read, it answers from that transaction's
  snapshot (MySQL's `REPEATABLE READ`), which may predate a change committed since; and even a current read does not
  stop the rule changing before the session it admits commits. It is for answering, not for admitting under a lock.
- `DatabaseEnforcement::lock($tenantId, $application, $connectionIds)` is what an admission takes first, inside its
  transaction on the storage connection: the package's redemption (`HandoffRecheck::lock()`, before the code) and the
  locked steps of a completion (`Completion\CompletionLocks::take()`). While the feature is off it answers `null` with
  no statement, no row and no inheritance call. Otherwise the inheritance contract names the enforcing tenant,
  `EnforcementLock::acquire()` upserts that tenant's row unconfigured unless it has one (never changing an existing
  row's values) and reads it locked, and `EnforcementFinder::lockConnections()` locks the connections given and, for a
  rule that is on, those it names, in one statement in ascending id order. The `Enforcement\LockedEnforcement` answers
  `policy()` from the locked rows (the same answer `policy()` gives for the same state) and `isCurrent()`, which asks
  the inheritance contract again; an admission whose enforcing tenant moved refuses (`connection_unavailable`) rather
  than lock another tenant's row out of order. Held until the admission's transaction ends, the lock makes a change to
  the rule, or a disable of a satisfying connection, wait for the admission, whose session its revocation then sees, or
  makes the admission wait for the change and see it.
- An application that binds its own `Contracts\Enforcement` is asked as it is bound, under the connection's lock alone;
  the package locks nothing of its own enforcement then. Such a contract must itself serialise an admission against
  changes to its rule through the session's commit (a current read alone is not enough), and its revocation must find
  sessions with current reads. A custom `Contracts\EnforcementInheritance` is asked inside the admission's transaction,
  before the locks and again under them, so it must answer in a transaction-safe way: from state that does not change
  under the transaction, or with a current read.
- `Enforcement\EnforcementService` (`@api`, resolved per request) is the one helper that changes a rule. `get()` answers
  an `EnforcementSummary` from the write connection. `update($tenantId, $enabled, $connectionIds, $client, $caller)`
  goes in a fixed order, and every refusal writes, revokes and reports nothing:
  1. the feature switch: off is `refused` with `feature_disabled`;
  2. the ids, validated as a whole: each a string of 1 to 26 bytes (`connection_ids.<n>` `invalid_type` or
     `invalid_format`, `<n>` its position in the list given), de-duplicated silently, at most
     `EnforcementService::MAX_CONNECTIONS` (50, `connection_ids` `too_many`), at least one while turning it on
     (`connection_ids` `required`), and each a connection of this tenant through `Connections\ConnectionFinder`
     (`connection_ids.<n>` `unknown`, the same for another tenant's connection as for an id with no connection, so no
     other tenant is revealed); any violation is `invalid` (`settings_invalid`) with every violation, in position order;
  3. the stored rule: the same switch and the same set of ids, in any order, looks `unchanged`, and skips step 5; it is
     answered `unchanged` only once step 6's locked read agrees, since the first read may come from the snapshot of a
     transaction the caller opened, and a change found there asks freshness before it is made;
  4. turning it on: one of the connections given must be enabled with `has_completed_sign_in` set, so a misconfigured
     connection cannot lock the tenant out (SSO-4.3), else `completed_sign_in_required`; turning it off needs none;
  5. freshness: `Freshness\FreshnessGate::check(FreshnessOperation::ENFORCEMENT_UPDATE)`, `sso.enforcement.update` with
     its configured maximum age (SSO-2.12); `stale` is `freshness_required`;
  6. one transaction on the storage connection (retried up to three times after a deadlock when it is the outermost):
     lock the tenant's row, then the connections given, steps 2 to 4 judged again on the locked rows, the write through
     the model (`enabled`, `connection_ids` sorted and unique, a new `version`, `changed_at` from the clock), the
     revocation when the rule is now on, and the report.
- Lock order: a tenant's enforcement row, then connection rows in id order (one locking statement by id, ordered by
  id, with the tenant compared byte for byte in PHP), then (for an admission) its request or code. Every read under the
  lock that decides the write is a locking read, since a plain read answers from the snapshot of a transaction the
  caller opened (MySQL's `REPEATABLE READ`). A connection's disable and delete (`Connections\ConnectionLifecycle`) take
  the same order: they lock no enforcement row, then the connection, and call `SessionRevocation` with
  `RevocationScope::connection()` inside their transaction.
- A tenant's row is locked through `EnforcementLock::acquire()`, the one insert-unless-exists the writer and every
  admission share: an upsert keyed by `tenant_hash` that inserts the row unconfigured (off, no connection, no version,
  no time), or leaves an existing row exactly as it is, then a locking read of the row. A locking read of a row that
  does not exist would take a gap lock on MySQL, and racing first lockers would deadlock on each other's gap locks; the
  upsert instead locks the existing row exclusively at once (`ON DUPLICATE KEY UPDATE`, `ON CONFLICT ... DO UPDATE`),
  so they queue on the row, inside a caller's transaction too. The writer, when its first read saw a configured row,
  locks it with a locking read alone. A change refused after the lock leaves an unconfigured row behind, which stores
  no rule; it is kept, not deleted, so a transaction waiting on it never loses the row it waits for.
- On PostgreSQL under `REPEATABLE READ`, a transaction that waited on the row while another changed it may fail to
  serialise (SQLSTATE `40001`) instead of seeing the change. It propagates: the writer retries it only as the
  outermost transaction (with its deadlocks), and inside a caller's transaction, as for an admission, the caller
  retries the whole transaction, never a part of it.
- Revocation runs synchronously inside the change's transaction, after the write and before the report, whenever the
  rule is now on (turned on, or its set changed while on): `SessionRevocation::revoke(RevocationScope::tenant($policy))`
  with `$policy` the `EnforcementPolicy::required()` of the tenant, the given connections that are enabled and the new
  version, the contract resolved from the container at that moment. Turning it off revokes nothing. An adapter writes
  through the same Laravel connection as the package, so its writes commit or roll back with the change; one that writes
  through another connection is not atomic with it. An exception from the revocation rolls the whole change back (no
  row, no new version, no event) and propagates as a server error.
- Each change is reported once, inside its transaction, through `Administration\EnforcementEvents::changed()`
  (`EnforcementChanged`, with the tenant, the acting identity, `enabled`, `connectionIds`, `version` and
  `previousVersion`, `null` for a tenant's first change, made on no row or on an unconfigured one), dispatched after
  commit and never when it rolls back (SSO-10.5). The event only reports: security never depends on a listener
  (SSO-9.3).
- `Enforcement\ExemptionGate::admit($policy, $application, $identity, $client, $sessionId)` (`@api`) is what an adapter
  calls when a session in an enforcing tenant would otherwise be refused (SSO-4.4, SSO-9.3). A policy that requires
  nothing answers `not_exempt` with nothing asked or reported. Otherwise it asks `EnforcementExemption`, resolved from
  the container on each call; `exempt` is reported once through `EnforcementEvents::exemptionUsed()` (`ExemptionUsed`,
  after the storage connection's open transaction commits, at once when none is open) and returned. An exception from
  the contract propagates: the gate never answers `exempt` when it cannot tell.
- Every outcome of a change is an `Enforcement\EnforcementResult` (status `Enforcement\Enums\EnforcementStatus`):
  `updated` or `unchanged` with an `EnforcementSummary`; `refused` with `feature_disabled`, `freshness_required` or
  `completed_sign_in_required`; `invalid` with `settings_invalid` and its `Connections\SettingViolation`s. A violation
  names a position and a code, never an id.

## Success Path

1. An administrator enables a connection and signs in through it once, which sets `has_completed_sign_in`.
2. The administration screen calls `update($tenantId, true, [$connectionId], $client, $caller)`: the id is the tenant's,
   the connection has completed a sign-in, freshness answers `fresh`, and in one transaction the row is written with a
   new version, the revocation removes the sessions the rule no longer allows, and `EnforcementChanged` is queued.
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
- A change racing an admission (a redemption writing a session in its transaction, or a completion): whichever locks
  the row first, the other waits. The change that waited revokes, with current reads, the session the redemption
  committed; the redemption or completion that waited sees the new rule and refuses with `enforcement_unsatisfied`. No
  committed session violates the committed rule; a serialisation failure on PostgreSQL is the other safe outcome.
- A revocation that throws, a database error, an exemption contract that throws and an inheritance contract that throws
  all propagate (SSO-11.4). Inside the application's own transaction, a deadlock propagates rather than being retried.
- A rule left with no enabled connection stays on and admits nobody but the exempt; turning it off, or naming an
  enabled connection, is the way out.

## Implementation Anchors

- `src/Enforcement/DatabaseEnforcement.php`, `EnforcementFinder.php`, `EnforcementLock.php`, `LockedEnforcement.php`,
  `EnforcementService.php`, `EnforcementResult.php`, `EnforcementSummary.php`, `ExemptionGate.php`,
  `Enums/EnforcementStatus.php`; `EnforcementPolicy.php`, `TenantHash.php`, `OwnTenantInheritance.php`,
  `NoExemptions.php`, `Enums/ExemptionOutcome.php`.
- `src/Contracts/Enforcement.php`, `EnforcementInheritance.php`, `EnforcementExemption.php`, `SessionRevocation.php`;
  `src/Revocation/RevocationScope.php`, `NoSessionRevocation.php`, `Enums/`.
- `src/Models/TenantEnforcement.php`, `database/migrations/2026_11_02_000001_create_sso_enforcement_table.php`.
- `src/Administration/EnforcementEvents.php`; `src/Events/EnforcementChanged.php`, `ExemptionUsed.php`.

## Authoritative Tests

- `tests/Feature/Enforcement/DatabaseEnforcementTest.php`, `EnforcementServiceTest.php`, `ExemptionGateTest.php`,
  `EnforcementLockTest.php` (the unconfigured row and its answers, an existing row never changed, `lock()`'s order and
  policy, nothing with the feature off).
- `tests/Unit/Enforcement/EnforcementResultTest.php`, `EnforcementSummaryTest.php`, `EnforcementPolicyTest.php`,
  `EnforcementDefaultsTest.php`; `tests/Unit/Revocation/RevocationScopeTest.php`.
- `tests/Integration/Enforcement/EnforcementRevocationTransactionTest.php`, `ConcurrentEnforcementChangesTest.php`
  (MySQL and PostgreSQL, plainly and inside a caller's transaction), `EnforcementAdmissionRaceTest.php` (a redemption
  writing a session racing a change, both orders, a stored rule and none), `EnforcementMigrationTest.php`.
- `tests/Performance/EnforcementQueryBudgetTest.php`.

## Change Triggers

- A change to what `policy()` answers, to when it reads, or to the feature switch's effect.
- A change to the validation, the order of a change, the completed sign-in rule or the freshness operation.
- A change to the lock order, the unconfigured row and its upsert, who takes the lock, or where the revocation is
  called; any new caller of `SessionRevocation`; a change to what a custom enforcement or inheritance contract must
  guarantee.
- A new outcome or reason of `EnforcementResult`, or a change to the exemption gate.
