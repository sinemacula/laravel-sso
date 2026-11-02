# Links

## Purpose

This note records how a verified result is linked to an identity (SSO-8.2 to SSO-8.4, SSO-6.9, SSO-1.5, SSO-4.5):
what a link is keyed by, how the package's link store resolves a result and creates a link under its uniqueness and
the link limit, and how the link helper lists an identity's links and removes one, revoking the identity's sessions
through the connection in the same transaction. The tables, models and lock order every flow shares are in `flows.md`;
the state machine that reserves and activates links by a verified domain (SSO-8.8) is in `linking.md`.

## Invariants

- A link is keyed by `Links\LinkSubject`: the issuer (1 to 1024 bytes), the subject (1 to 1024 bytes) and, for SAML, the
  `NameID` format (1 to 255 bytes, `null` for none), each exactly as received; the subject is never trimmed or
  normalised, so `Subject`, `subject` and `subject` followed by a space are three subjects (SSO-6.9).
  `LinkSubject::of($result)` takes the three from a `Results\VerifiedResult`; anything out of bounds is an
  `InvalidArgumentException` naming no value.
- `LinkSubject::key()` is the stored `subject_key`: the lower-case hex SHA-256 of
  `'sso-link-v1' . "\0" . lp(issuer) . (format === null ? 'N' : 'F' . lp(format)) . lp(subject)`, where
  `lp(x) = pack('N', strlen(x)) . x`. The length prefixes keep any two different triples apart, the marker keeps a
  missing format apart from a set one, and the version tag names the layout, so a later layout is a new tag, never a
  silent change. The key is the only column a lookup compares, unique with `connection_id`, so no collation can fold
  or trim a subject; the subject itself is kept byte for byte in a binary column (`Models\Casts\BinaryString`).
- `Contracts\Linker` defaults to `Links\NoLinks`, which links nothing. `Links\LinkStore` implements it over the links
  table; it is not the default: the application binds it (scoped), or `laravel-iam` does, under which it also answers
  `laravel-authentication`'s link contract (SSO-8.3, AUTH-3.9).
- `LinkStore::resolve($result)` reads the row with `connection_id` the result's connection and `subject_key` its
  subject's key, of any state, by a locking read (`lockForUpdate()`) on the write connection (SSO-11.3), and compares
  the connection, issuer, format and subject again in PHP, byte for byte: a row whose key alone matches is not the
  subject's. A result reaches only the links of the connection it completed through, so another connection, of any
  tenant, with the same issuer and subject resolves nothing (SSO-8.2). It answers a typed `Links\LinkResolution`:
  `absent`, `linked`, `reserved` or `suspended`. A reserved link and a suspended one resolve nothing, and neither is an
  unlinked subject. Nothing else in the result (a name, an email, any mapped attribute) is read.
- A link it resolves has `last_used_at` stamped with the clock's now by one statement,
  `UPDATE ... WHERE id = ? AND (last_used_at IS NULL OR last_used_at <= now - 60 s)`: at most one change a minute per
  link (`LinkStore::LAST_USED_RESOLUTION_SECONDS`), without touching `updated_at`. The statement is sent on every
  resolution that finds a link, and changes nothing within the minute.
- The SSO-8.8 provenance rule: an active link with verified domain provenance whose identity is no longer known by
  `Contracts\PrincipalScope` to hold only principals of the tenant is suspended for good, resolving nothing until a
  confirming `link` by an independently authenticated caller (`linking.md`). `LinkStore::suspend()` stores it, latched,
  raises the connection's `links_version` and reports `LinkSuspended`; a resolution that finds it answers `suspended`,
  and `Linking\ScopeWidening` reports it
  from the application's principal mutation, which is the only way a principal added and removed between two checks is
  seen.
- `Linking\ScopeWidening::widened($identity, $tenantId)` runs first in the application's principal-change transaction,
  on the storage connection (a `LogicException` outside one). `$tenantId` is the new principal's tenant, compared
  exactly, or `null` for a platform principal. A plain read on the write connection finds the identity's rows with
  verified domain provenance and the tenants of their connections; a connection of the new principal's tenant is left
  alone. For the others, in ascending id order: the connection's row is locked, then the identity's rows in it; a
  reservation is deleted (`Links\ReservationWithdrawal::ofRows()`, raising `links_version`); an active link is
  suspended; and for each active or already suspended link `Contracts\SessionRevocation::revoke()` is called with
  `RevocationScope::identityLink($tenantId, $connectionId, $identity, $linkId)`, reason `scope_widened`, inside the
  transaction. A revocation that throws rolls the change back.
- `ScopeWidening::assertSettled($identity, $tenantId)` runs after the application took its principal guard and wrote the
  principal. A shared lock reads the identity's active and reserved rows with that provenance again, current, in other
  tenants' connections; any is a `RuntimeException`, and the application retries its whole transaction. The package's
  locks never come after an application's guard, so this read cannot lock a connection; a redemption holding such a row
  while waiting for the guard is a deadlock the database aborts, which is safe in the same way. Without the application
  taking part, nothing can suspend a link between two checks (`docs/guides/linking-by-domain.md`).
- `LinkStore::create($connection, $subject, $identity, $origin, $actor, $application, $purpose, $reference)` runs in
  one transaction on the storage connection (a savepoint inside the caller's), in this order:
  1. the connection's row is read again locked through `Connections\ConnectionFinder::findForUpdate()`, which
     serialises every creation in the connection; a connection that does not exist (or is not the tenant's the model
     names) is a `LogicException`;
  2. the identity's links in the connection are read by a locking read and counted in PHP, the identity compared byte
     for byte: active links, and reserved links whose `reservation_expires_at` is after now (one that expires at now or
     earlier, or has no expiry, does not count). The rows are counted in PHP because PostgreSQL refuses `FOR UPDATE`
     with an aggregate;
  3. `Contracts\LinkLimit::maxLinks($identity, $connection)`, resolved from the container at that moment, is asked; an
     answer below one is a `LogicException` naming the bound class;
  4. a count at or above the limit is `link_limit_reached`;
  5. the link is inserted through the model, `active`, with its `provenance` the origin given, which is
     `verified_domain` only for `LinkOrigin::VERIFIED_DOMAIN`, in a savepoint of its own; the unique index on
     (`connection_id`, `subject_key`)
     refusing it (`UniqueConstraintViolationException`) is `subject_already_linked`, for this identity or another, and
     the savepoint keeps the caller's transaction usable (PostgreSQL aborts a transaction on a failed statement);
  6. the connection's `links_version` is raised by one, so the insert also writes the connection's row: a PostgreSQL
     `REPEATABLE READ` transaction whose snapshot predates the creation (a subject migration that waited on the lock,
     say) fails to serialise when it locks the row, rather than go on without the new link, which neither its locking
     read nor its delete would see;
  7. `LinkCreated` with the origin is reported after commit, with the connection, tenant, protocol, identity, acting
     identity and, for a flow, its application, purpose and public reference.

  An expired reservation of the subject is deleted first, since it holds nothing, under a new reservation identity if it
  is ever reserved again; a live reservation holds the subject, so a creation is `subject_already_linked`, and a `link`
  flow is refused `link_reserved` before it gets here.

  Uniqueness is not configurable; the limit is (SSO-8.4). Any other error propagates (SSO-11.4).
- `Links\LinkCreation` (status `Links\Enums\LinkCreationStatus`) answers `created` with a `LinkSummary`,
  `subject_already_linked` or `link_limit_reached`, each refusal with its `FailureReason` (`reason()`), `isCreated()`
  and `isRefused()`. A refusal wrote and reported nothing, and never says which identity holds a subject.
- `Links\LinkService` (`@api`, resolved per request) takes an identity as an `IdentityReference` or the string `me`,
  which names the caller passed; `me` without a caller, or any other string, is an `InvalidArgumentException`.
  - `list($identity, $caller)` answers the identity's `LinkSummary`s in every connection of every tenant (SSO-1.5),
    read on the write connection, the identity compared byte for byte, ordered by `created_at` then `id`; a link whose
    connection no longer exists is left out.
  - `remove($identity, $linkId, $caller, $actor)`, in this order, a refusal deleting, revoking and reporting nothing:
    1. the identity is resolved;
    2. the link is found by its id and the identity (a plain read on the write connection); a missing link and another
       identity's are both `link_not_found`, so nothing is revealed;
    3. `Freshness\FreshnessGate::check(FreshnessOperation::LINK_REMOVE)` (`sso.link.remove`, SSO-2.12); `stale` is
       `freshness_required`;
    4. one transaction on the storage connection: the link's connection row is locked, then the link is read again
       locked (gone, reassigned to another identity or orphaned is `link_not_found`), deleted through the model,
       `Contracts\SessionRevocation::revoke(RevocationScope::identityInConnection($tenantId, $connectionId,
       $identity))` is called inside the transaction (SSO-4.5), and `LinkRemoved` is reported after commit.

    Removing the identity's last link is allowed. A revocation that throws rolls the delete back, reports nothing and
    propagates; an adapter that writes through the same Laravel connection commits or rolls back with the removal
    (decision D5).
- `Links\LinkResult` answers `removed` with the `LinkSummary` as it was, or `refused` with `link_not_found` or
  `freshness_required` (any other reason is an `InvalidArgumentException`); `isRemoved()`, `isRefused()`.
- `Links\LinkSummary` holds the id, connection id, tenant id, protocol, issuer, `NameID` format, state, verified domain
  provenance, created and last used times, with a snake_case `jsonSerialize()` (times in UTC to the second). It never
  holds the subject.
- `Links\LinkReservations` is the one place a reserved row is written, and `Links\ReservationWithdrawal` the one place
  reservations are withdrawn: by connection (a disable, a deletion, a trust change, a linking settings change), by
  domain (a suspension, a removal, a lapse) or by the rows of an identity whose scope widened. Each raises
  `links_version` when it deleted anything, as creation, replacement and activation do, so a PostgreSQL
  `REPEATABLE READ` transaction whose snapshot predates the change fails to serialise when it locks the connection's
  row, rather than miss it.
- `Links\LinkEvents` (`@internal`) builds each context through `Events\EventContexts::make()` and dispatches through
  `Events\AfterCommitDispatcher`, so an event reaches listeners once the storage connection's transaction commits and
  never when it rolls back (SSO-10.5). No event carries the subject; the public reference is the only flow identifier
  (SSO-9.8). Refusals report nothing and fire no `FlowFailed`: a helper's refusal is its result.
- Lock order, as `flows.md` sets it: a connection's row, then its links. Every read under the lock that decides a write
  is a locking read, since a caller's MySQL `REPEATABLE READ` transaction answers a plain read from an older snapshot;
  the removal's first, plain read is confirmed by the locking read before anything is written.

## Success Path

1. The application binds `LinkStore` as the `Linker`.
2. A redeemed `link` flow (or provisioning) calls `create()`: the connection is locked, the identity has room under the
   limit, the link is inserted, and `LinkCreated` reaches listeners once the transaction commits.
3. A later `sign_in` result through the same connection with the same issuer, format and subject resolves to the
   identity, and the link's last use is stamped.
4. The identity's account screen lists its links with `list('me', $caller)` and removes one with
   `remove('me', $id, $caller, $actor)`; the identity's sessions through that connection are revoked with the delete,
   and `LinkRemoved` is reported.

## Failure / Edge Cases

- Two creations of one subject for different identities race: the connection's lock serialises them and the second is
  `subject_already_linked`. Two subjects for one identity at a limit of one race: the second's locking count sees the
  first and it is `link_limit_reached`. Both hold inside a caller's own transaction.
- An expired reservation counts for nothing: a creation or a new reservation of the same subject deletes it first, and
  a handoff bound to it activates nothing, since the replacement has another reservation identity.
- A principal added and removed between checks suspends every domain link of the identity for good, and revokes the
  sessions established through them, so long as the application's principal mutation calls `ScopeWidening`.
- A link or reservation made between `widened()`'s read and the application's guard is a `RuntimeException` from
  `assertSettled()`, which rolls the principal change back to be retried.
- A bound limit that answers zero or less is a misconfiguration, never a silent refusal.
- A link deleted or reassigned between the removal's first read and its lock is `link_not_found`, with nothing revoked.
- A revocation that throws, and any database error, propagate (SSO-11.4).

## Implementation Anchors

- `src/Links/LinkSubject.php`, `LinkStore.php`, `LinkCreation.php`, `Enums/LinkCreationStatus.php`,
  `LinkService.php`, `LinkResult.php`, `LinkSummary.php`, `LinkEvents.php`, `LinkResolution.php`,
  `LinkReservations.php`, `ReservationTerms.php`, `ReservationWithdrawal.php`, `ReservedCandidate.php`; `NoLinks.php`,
  `OneLinkPerConnection.php`, `Enums/LinkState.php`, `Enums/LinkOrigin.php`, `Enums/LinkResolutionStatus.php`.
- `src/Linking/ScopeWidening.php`, `src/Connections/LinkingPolicyService.php`.
- `src/Contracts/Linker.php`, `LinkLimit.php`, `PrincipalScope.php`, `SessionRevocation.php`;
  `src/Revocation/RevocationScope.php`.
- `src/Models/Link.php`, `src/Models/Casts/BinaryString.php`,
  `database/migrations/2026_11_03_000000_create_sso_links_table.php`.
- `src/Events/LinkCreated.php`, `LinkRemoved.php`, `LinkActivated.php`, `LinkSuspended.php`, `LinkConfirmed.php`.

## Authoritative Tests

- `tests/Unit/Links/LinkSubjectTest.php` (independent key vectors and bounds), `LinkCreationTest.php`,
  `LinkResultTest.php`, `LinkSummaryTest.php`, `LinkResolutionTest.php`, `ReservationTermsTest.php`.
- `tests/Feature/Linking/ScopeWideningTest.php`, `ReservationWithdrawalTest.php`, `DomainLinkEligibilityTest.php`,
  `DomainLinkingEventSequenceTest.php`.
- `tests/Feature/Links/LinkStoreTest.php`, `LinkServiceTest.php` (a removal's re-read is a locking read, inside its
  transaction), `LinkEventSequenceTest.php`.
- `tests/Integration/Links/ConcurrentLinkCreationTest.php` and `ConcurrentLinkRemovalTest.php` (MySQL and PostgreSQL,
  plainly and inside a caller's transaction), `LinkRemovalTransactionTest.php`, `LinkSubjectStorageTest.php` (every
  engine), `tests/Integration/Linking/ConcurrentReservationTest.php`, `ConcurrentActivationTest.php`.
- `tests/Performance/LinkStoreQueryBudgetTest.php`, `LinkingQueryBudgetTest.php`.

## Change Triggers

- A change to the key's layout (a new version tag), to what a lookup compares, or to the bounds of a subject's parts.
- A change to what counts toward the limit, to the order of a creation or a removal, or to the lock order.
- A change to the SSO-8.8 provenance rule, or to the reservation, activation or voiding of links (`linking.md`).
- A new caller of `create()` or of `SessionRevocation`, a new outcome of `LinkCreation` or `LinkResult`.
