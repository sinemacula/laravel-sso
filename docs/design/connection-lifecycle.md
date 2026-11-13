# Connection Lifecycle and Trust Changes

## Purpose

This note records how a connection is disabled and deleted, what a change to the trust of a connection does to the
flows in flight through it, and how a change that alters what the connection's subjects mean is refused while it has
links and made only through an explicit migration (SSO-2.1, SSO-2.11, SSO-2.12, SSO-2.13, SSO-4.5, SSO-10.3,
SSO-10.5). It builds on `flows.md` (the tables, the lock order, `voided_at`), `connection-settings.md` (the update
helper), `keys.md` (trusted certificates), `domains.md` (`DomainWithdrawal`) and `enforcement.md`
(`SessionRevocation`).

## Invariants

### Voiding what is in flight

- `Connections\InFlightVoider` (`@internal`, readonly, not final) is the one place a connection's flows are voided.
  `voidFor($locked, $spared = null)` runs inside the caller's transaction on the storage connection, with the
  connection's row already locked; called outside a transaction it is a `LogicException`, so a void never commits apart
  from its change.
- It sets `voided_at` and `updated_at` to the clock's now, in two statements:
  - on the connection's authorisation requests with `completed_at` and `voided_at` both unset, so a request a
    completion has consumed but not yet finished is voided too, but for the one request `$spared` names (an unknown
    `kid` refetch spares the request whose token asked, `oidc-discovery.md`);
  - on the connection's handoff codes with `redeemed_at` and `voided_at` both unset.
- A request or code voided before keeps its first `voided_at`; a finished request and a redeemed code are left as they
  are; another connection's rows are never touched.
- It then raises the connection's `trust_version` by one and calls `reservationsVoided($locked)`, which deletes the
  connection's open link reservations (state `reserved`, `Links\ReservationWithdrawal`), under the same lock and in the
  same transaction, as `Domains\DomainWithdrawal::linkingWithdrawn()` does for a domain's withdrawal (SSO-8.8,
  `linking.md`).
- Every completion and redemption takes the connection's row lock first (`flows.md`), so a void either waits for a
  completion or redemption that holds the lock, and then finds its request finished or its code redeemed, or is waited
  for, and the completion refuses a voided request with `connection_unavailable` and the redemption a voided code with
  `handoff_unknown`.
- The void's updates see a row inserted since the change's snapshot on MySQL and under PostgreSQL's `READ COMMITTED`,
  but not under PostgreSQL's `REPEATABLE READ`. So every insert it must void also writes the connection's row: storing
  an authorisation request (`Flows\AuthorizationRequestService`) and issuing a handoff code
  (`Handoffs\DatabaseHandoffStore`) each raise the connection's `flows_version` by one under its lock, and a change
  whose snapshot predates either insert fails to serialise (SQLSTATE `40001`, which propagates) when it locks the
  connection, before it voids or deletes anything. No change commits with a request or code left unvoided, and no
  deletion with one left behind.

### Which changes void

| Change                                                                  | Voids | Freshness                                           |
|-------------------------------------------------------------------------|-------|-----------------------------------------------------|
| `ConnectionLifecycle::disable()`                                        | yes   | `sso.connection.disable`                            |
| `ConnectionLifecycle::delete()`                                         | yes   | `sso.connection.delete`                             |
| `ConnectionService::update()` that asks `sso.connection.trust`          | yes   | `sso.connection.trust`, and what else it asks       |
| `ConnectionService::update()` that asks only another operation, or none | no    | what it asks                                        |
| `KeyService::trustCertificate()` of a metadata signing anchor           | yes   | `sso.connection.trust`                              |
| `KeyService::trustCertificate()` of an identity provider certificate    | no    | `sso.connection.trust`                              |
| `KeyService::distrustCertificate()`                                     | yes   | `sso.connection.trust`                              |
| A metadata refresh that removes a certificate or moves the endpoint     | yes   | none: a system job (`metadata-refresh.md`)          |
| A metadata refresh that only adds certificates                          | no    | none                                                |
| `KeyService::addNext()`, `makeCurrent()`, `retire()`                    | no    | `sso.keys.rotate`                                   |
| `SubjectMigration::migrate()`                                           | yes   | `sso.connection.trust`, `sso.link.remove`, and more |

A key of the service provider's own keeps what subjects mean and what the identity provider signs, so its rotation
voids nothing. An identity provider certificate trusted beside the others only adds a key a signature may verify with,
so a provider's next certificate can be trusted ahead of its switch without voiding its own flows; removing one, and
any change to the metadata signing anchors, voids. Each voiding change raises the connection's trust version, which
every authorisation request stores when it starts: a start whose connection's trust version moved between its read and
its insert stores nothing, and a completion whose request's trust version is not the connection's is refused at
consumption and again under its lock, as a voided one is. Every handoff code keeps the trust version it was issued
under, and `HandoffRecheck` refuses one whose version is not the connection's under the redemption's lock as
`connection_unavailable`: the package's codes are voided as well, and an application's own, which the package never
voids, are refused by the version alone (`handoffs.md`). Enabling a disabled connection raises the version too, so a
code issued before a disable is never redeemed after the enable. A refused or unchanged change voids nothing.

### Disabling and deleting

- `Connections\ConnectionLifecycle` (`@api`, final, readonly, resolved per request) is scoped to a tenant as
  `ConnectionService` is: another tenant's connection is `connection_not_found`, exactly as an unknown one, and an
  empty or overlong tenant id is an `InvalidArgumentException`.
- Both go in one order: one transaction on the storage connection (a savepoint inside the caller's) reads the
  connection with `lockForUpdate()`, is `connection_not_found` without it, and asks the freshness contract
  (`freshness_required`) before anything else; a deletion locks the connection's domain claims first.
- `disable()` asks `sso.connection.disable`, with its own maximum age, even of a disabled connection. It reads
  `enabled` from the locked row: a disabled connection is `unchanged`, writing, voiding, revoking and reporting
  nothing, so the answer of the first read is always confirmed under the lock. Otherwise it sets `enabled` off, voids
  what is in flight, revokes, and reports `ConnectionDisabled`. Its domains, links and keys are kept, so enabling it
  again restores it.
- `delete()` asks `sso.connection.delete`. Under the connection's lock it locks the connection's domain claims (by
  `connection_id`, in id order) and calls `DomainWithdrawal::linkingWithdrawn($locked, $claim)` for each verified one,
  before anything is deleted; voids what is in flight; deletes the connection's domains, authorisation requests,
  handoff codes, links and keys, in the lock order, then the connection; revokes; and reports one `ConnectionDeleted`,
  with the connection as it was read, and no event per link removed: the removals are reported by the connection's own
  event.
- A connection whose protocol is no longer registered can be disabled and deleted: either leaves less access.
- The result is a `ConnectionResult`: `disabled` (with the summary), `deleted` (with none, since the connection is
  gone), `unchanged`, or `refused` (`connection_not_found`, `freshness_required`).

### Revocation

- `disable()` and `delete()` call `Contracts\SessionRevocation`, resolved from the container at that moment, with
  `RevocationScope::connection($tenantId, $connectionId, $reason)` (kind `connection`, reason `connection_disabled` or
  `connection_deleted`), inside their transaction, after the write and before the report (SSO-4.5).
- A subject migration revokes `RevocationScope::identityInConnection()` (reason `link_removed`, naming the old link's
  id) for the identity of each link it removes and each relinked link of verified domain provenance, whose new row a
  later revocation by link could not reach the old sessions through, and none for any other link it relinks, whose
  identity keeps signing in through the connection.
- An exception the revocation throws rolls the whole change back, reports nothing and propagates.

### Changes to what subjects mean

- A protocol's `subjectNames()` lists the settings a change to which may alter what existing subjects mean: the OIDC
  `issuer` and `client_id`; the SAML `idp_entity_id`, `subject_source`, `subject_attribute` and `name_id_format`.
- `ConnectionService::update()` refuses a change to any of them with `connection_has_links` while the connection has a
  link: an active one, or a reserved one whose reservation expires after now, found by a locking read on the write
  connection. Freshness is asked first, as for every update, so a stale caller is `freshness_required` whatever the
  links. A link of another connection does not count; a reservation that expired at now or before does not count.
- `Connections\SubjectMigration` (`@api`, final, readonly, resolved per request) is the explicit way to make such a
  change. `migrate($tenantId, $connectionId, $changes, $relinks, $removals, $client, $caller)` takes the change as
  `update()` does and an exhaustive disposition of the connection's links: the relinks, each link id mapped to a list of
  its subject under the new meaning, then optionally its NameID format and its issuer (the format `null` or left out for
  none, and the issuer, when `null` or left out, the link's own, so a migration that changes the issuer gives the new
  one); and the removals, a list of link ids. Every link the connection has when the migration runs must be in exactly
  one of the two. Nothing is removed by omission, so a link created after the caller read the links to prepare its call
  is never silently removed or kept: the migration is refused and the caller prepares it again.
- In one transaction on the storage connection (a savepoint inside the caller's), in this order:
  1. the connection is read locked (`connection_not_found`, `protocol_unavailable`), then its links, locked, in id
     order;
  2. the disposition is judged against the locked links: a link in neither the relinks nor the removals (one created
     since the caller prepared the call included), an id in both, or an id that is not one of the connection's links
     (another connection's link, an unknown id, a removal that is not a string) is refused with `links_unaccounted`,
     with nothing asked, written or reported; a removal listed twice counts once. A link created while the migration
     waited for the lock is among the locked links on MySQL and under PostgreSQL's `READ COMMITTED`; under PostgreSQL's
     `REPEATABLE READ`, whose snapshot may predate it, the creation's write to the connection's `links_version` makes
     the migration's lock fail to serialise (SQLSTATE `40001`, which propagates) rather than go on without the link;
  3. the change is validated as `update()` validates one (it is `ConnectionService::changeLocked()`, the narrow
     internal method `update()` runs once it holds the lock), with the relinks after the change's own violations, each
     at `relinks.<id>`: `not_allowed` for a reserved link (which may be removed, not relinked), `invalid_type` for
     anything but a list of one to three parts (a string subject, then a string or `null`), `invalid_format` for an
     empty or overlong subject, issuer or format; any violation is `invalid` (`settings_invalid`), and a change that
     changes nothing is `unchanged`, touching no link;
  4. freshness is asked through `FreshnessGate::checkAll()` with `sso.connection.trust`, each operation the change
     asks and `sso.link.remove`, in `FreshnessOperation`'s order (`freshness_required`);
  5. in a savepoint: the change is written and reported, what is in flight voided, every link of the connection
     deleted and reported removed, and the sessions of each identity whose link is removed, or relinked from a verified
     domain, revoked;
  6. each relinked identity is linked to its new subject through `Links\LinkStore::create()` with the origin
     `migration`, in the order the relinks are given. A link of verified domain provenance keeps it, since only a
     confirming `link` clears it (SSO-8.8), so the row is still judged by `Contracts\PrincipalScope` and found by
     `Linking\ScopeWidening`; any other relinked link's provenance is `migration`. A new subject already linked in the
     connection (another relink's included) is `duplicate` at `relinks.<id>`, an identity at its link limit
     `too_many`; either is `invalid` and rolls the whole migration back, the change, the removals, the revocations'
     writes and the voiding included.
- The result is `migrated` with the summary and the names of what changed, or a refusal as above.

### Events

| Operation   | Sequence, after commit                                                                                               |
|-------------|----------------------------------------------------------------------------------------------------------------------|
| `disable()` | `[ConnectionDisabled]`                                                                                               |
| `delete()`  | `[ConnectionDeleted]`                                                                                                |
| `migrate()` | `ConnectionUpdated`; a `LinkRemoved` per link, in id order; a `LinkCreated` (`migration`) per relink, in order given |
| Any refusal | none                                                                                                                 |

The migration's events are dispatched in that order because the change and the removals are reported inside a savepoint
that commits before the store's own transactions do; inside a caller's transaction they wait for its commit, in the
same order. No event carries a subject, a state value, a code or a verifier; the request's public reference is the only
flow identifier the package ever logs or reports, and none of these operations names one.

### Lock order

`flows.md`'s: the connection's row first, then its rows in the other tables. A deletion locks the connection, then its
domain claims, then voids its requests and codes and deletes in the order domains, requests, codes, links, keys. The
update and the migration lock the connection, then read its links with a locking read before they void its requests
and codes; every writer of those rows takes the connection's lock first, so the order beneath it cannot deadlock. Every
read under the lock that decides a write is a locking read (`lockForUpdate()`), since a caller's MySQL
`REPEATABLE READ` transaction answers a plain read from an older snapshot.

## Success Path

1. An administrator disables a connection: freshness is asked, the connection is turned off, every unfinished request
   and unredeemed code is voided, every session established through it revoked, and `ConnectionDisabled` reported.
2. An administrator deletes a connection: freshness is asked, each verified domain's dependants withdrawn, what is in
   flight voided, every row of the connection deleted, every session revoked, and `ConnectionDeleted` reported.
3. An administrator rotates a client secret or an endpoint: the update writes it, voids what is in flight, and reports
   `ConnectionUpdated`.
4. An administrator moves a connection to a new issuer: `update()` refuses with `connection_has_links`; the
   administrator calls `migrate()` with each kept link's subject under the new issuer and every other link listed for
   removal.

## Failure / Edge Cases

- A completion that consumed its request before a disable or trust change committed refuses it under the lock with
  `connection_unavailable` and issues no code; one that held the lock first issues its code, which the change then
  voids. A redemption after the change is `handoff_unknown`; one before it redeems, and the change leaves the code.
- A connection disabled or deleted between the first read and the lock is judged on the locked row: `unchanged` or
  `connection_not_found`.
- A revocation that throws, a database error, or a link the store refuses rolls everything back; only a refusal the
  helper makes is a value.
- A link reserved for a redemption cannot be relinked (`not_allowed`): relinking would activate it without the
  redemption's checks. It is removed with the others not relinked.

## Implementation Anchors

- `src/Connections/InFlightVoider.php`, `src/Connections/ConnectionLifecycle.php`,
  `src/Connections/SubjectMigration.php`.
- `src/Connections/ConnectionService.php` (`changeLocked()`, the has-links refusal, the voiding),
  `src/Connections/ConnectionResult.php` (`disabled`, `deleted`, `migrated`, `connection_has_links`).
- `src/Keys/KeyService.php` (the voiding of a certificate trusted or distrusted).

## Authoritative Tests

- `tests/Feature/Connections/ConnectionLifecycleTest.php`, `tests/Feature/Connections/TrustChangeVoidingTest.php`,
  `tests/Feature/Connections/SubjectMigrationTest.php`, `tests/Feature/Connections/LifecycleEventSequenceTest.php`.
- `tests/Feature/Connections/ConnectionServiceTest.php` (the has-links refusal),
  `tests/Feature/Keys/TrustedCertificatesTest.php` (the certificate voiding),
  `tests/Unit/Connections/ConnectionResultTest.php`.
- `tests/Integration/Connections/ConcurrentLifecycleTest.php`,
  `tests/Integration/Connections/ConcurrentFlowVoidingTest.php` (a trust change and a deletion under `REPEATABLE READ`
  after a flow inserted since their snapshot; MySQL and PostgreSQL),
  `tests/Integration/Connections/LifecycleRevocationTransactionTest.php`,
  `tests/Integration/Connections/ConnectionDeletionTest.php`.
- `tests/Performance/ConnectionLifecycleQueryBudgetTest.php`.

## Change Triggers

- A change that alters a connection's trust, or a new one, and whether it voids.
- A new table a connection owns rows in, which its deletion must delete, in the lock order.
- What `subjectNames()` lists, or what counts as a link for the has-links refusal.
- The migration's relink shape, its order of steps, or its events.
- The revocation scope or reason a lifecycle change revokes with.
