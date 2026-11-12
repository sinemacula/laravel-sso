# Linking, Provisioning and Evidence

## Purpose

This note freezes the completion and redemption state machine of linking (SSO-3.3, SSO-5.10, SSO-5.11, SSO-8.1 to
SSO-8.8, SSO-9.5, SSO-9.9): its stages, which transaction each write runs in, the lock order, the reservation and link
states, what the application's contracts must guarantee, and the events each operation reports. `completion.md` and
`flows.md` describe the steps; `links.md` and `handoffs.md` the stores. Linking through a verified domain, the `link`
purpose, provisioning, reauthentication and evidence all stand on this machine and do not change it.

## Invariants

### The lock order

The order is never broken: **identity guard**, enforcement guard, connections in ascending id order, the relevant domain
claim, the request, the existing code, the links, then the application's guards. Every re-read that decides a write is a
locking read on the write connection. An absent row is protected by the row that guards its insertion: a domain claim or
a link by the connection's row, and a verified domain link of an identity, in any connection, by that identity's guard.
A reservation's domain and identity are found by a plain read of the reservation, and confirmed under the lock by its
immutable binding.

The identity guard comes first because a principal mutation knows only an identity: it cannot take connections in order
without knowing which it needs, and a check made after its write would invert the locks. So principal widening,
reservation creation, activation and confirmation share `Linking\IdentityLock`: a row keyed by a digest of the
identity's type and id, materialised by insert-unless-exists on the storage connection, like the enforcement guard, and
never deleted. Holding it, nothing else can change the identity's verified domain links, in any connection, and a row
that does not exist yet is protected too.

Each of the four discovers what it needs by plain reads first, locks in order, and judges again under the locks; when
the candidates changed it refuses, and a caller's transaction is retried only whole:

| Flow             | Discovers, by plain reads                                                       | Candidates that changed                                                                                     |
|------------------|---------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------|
| Reservation, T2  | Before T2 opens: the subject's row, the domain claim, then the matched identity | An eligible identity whose guard was not taken is `reservation_invalid`; a row gone since is `link_changed` |
| Activation, TR   | The reservation's identity and domain                                           | A row no longer the handoff's, or of another identity, is `reservation_invalid`                             |
| Confirmation, TR | The connections holding the identity's verified domain links, once guarded      | A link in a connection not locked is `Exceptions\LinkCandidatesChanged`, retried whole                      |
| Widening, TW     | The connections holding the identities' rows, once guarded                      | A row in a connection not locked is `Exceptions\LinkCandidatesChanged`, retried whole                       |

Only a transaction whose `REPEATABLE READ` snapshot predates the change can reach `LinkCandidatesChanged`, and only on
MySQL: on PostgreSQL its guard fails to serialise first, since whatever changed the row wrote the guard. A caller's
transaction that read before it redeemed or widened has such a snapshot. The package's standalone redemption never does:
it reads the connection's tenant before its transaction opens, so for a `link` the guard is the first statement in it
and every plain read after it sees what the guard's previous holder committed; should it reach `LinkCandidatesChanged`
all the same, it restarts once from its transaction, and a second time propagates.

The guard's cost falls only on flows that touch linking. An ordinary linked sign-in reads its row, takes no guard and
locks no claim; a sign-in with the feature or the connection's linking off reads neither. A transaction holds one
identity's guard; one that changes several takes them in ascending order of `IdentityLock::digest()`. A widening of
several identities, such as a subtree of tenants moved, is one `widened()` call given them all: it takes every guard,
then locks the union of their connections in one statement, so a confirmation or a reservation of any of them never
holds a guard the widening waits on while waiting on a connection it holds. The call takes one tenant, whose connections
it spares for every identity given, so it suits identities that all gain a principal in the same tenant; identities
gaining principals in different tenants are not one call.

An application's guards come after the package's locks, in every path: its writers of verified emails, principals,
memberships and sessions take them in the same relative order, or they will deadlock against an admission. Every
contract an admission asks is asked once the package's link locks are held. At completion, what the guarded identity
holds is read before the matcher, the principal scope and the membership; at activation, the reservation's row and what
its identity holds; in a `link`, the identity's verified domain links and the subject's link, before freshness,
eligibility and the confirmation.

### The stages

| Stage                              | Transaction and writes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
|------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Entry and correlation              | None. The endpoint and application context is validated and the response correlated; attempt limiting keeps its own storage.                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Consumption, T1                    | Connection, then request. Request single-use record and `consumed_at`; expiry, voiding and trust are checked. Commits before validation.                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Validation                         | None. Provider calls and cryptography build the immutable `VerifiedResult`, the deadline (`VerifiedDeadlines`), the key-transition receipt, and the linking policy version of the connection the driver was given.                                                                                                                                                                                                                                                                                                                                                |
| Discovery                          | None. Only for a `sign_in` with a linking email, the feature and the connection's linking on (`Linking\ReservationDiscovery`): the bound linker must be `Contracts\LinkStorage`; a row holding the subject ends it; then the claim, and the matcher. It decides nothing.                                                                                                                                                                                                                                                                                          |
| Preparation, T2                    | Identity guard when one was found, enforcement guard, connections, relevant domain (none when the subject was held), request, links. Request authority, usability, metadata, the deadline and inheritance are rechecked. Replay is recorded once; the link resolves to a typed `LinkResolution`, a definite outside scope latching the suspension and revoking the link's sessions; enforcement and the purpose's rules (`Completion\Rules`, for a `reauthenticate` including the authentication-time window, whichever driver answered) run; domain eligibility. |
| Ordinary or reserved finish, in T2 | A linked result, an eligible `link` or `reauthenticate`, or a successful reservation: the bound handoff is issued, reservation and handoff committing together with one stored expiry; `completed_at` is set; completion events queue. A refusal discards any reservation made and completes without a code.                                                                                                                                                                                                                                                      |
| Provisioning boundary, from T2     | Only a genuinely unlinked `sign_in` holding no reservation (`StageOutcome::provision()`). Replay and `verified_at` commit; `completed_at` stays unset; no handoff. What lets it go on stays only in memory. `ResultVerified` is reported once, after commit.                                                                                                                                                                                                                                                                                                      |
| Synchronous dispatch               | No package transaction open. `ResultUnlinked` carries the exact result and the grant (`Completion\ProvisioningOffer`). Nothing dispatches it again.                                                                                                                                                                                                                                                                                                                                                                                                               |
| Provisioning, TP                   | The listener's own transaction on the same connection, for identity and membership. `Provisioning\ProvisioningHelper` claims the grant, takes the prescribed locks, checks the request's authority, ownership and limit, inserts the active provisioning link and raises `links_version`; its event waits for TP's outer commit.                                                                                                                                                                                                                                  |
| Grant closure                      | In `finally`, the grant is closed. A listener's transaction left open is rolled back and is a `LogicException`; a listener's exception ends the completion and authorises no resumption.                                                                                                                                                                                                                                                                                                                                                                          |
| Final continuation, T3             | The lock order again, with no domain. Trust and receipt, voiding, the deadline, metadata, enforcement and application policy are rechecked; the link resolves anew (`CompletionStep::isInContinuation()`). No second replay record, domain selection or dispatch. A handoff, `unlinked` or another refusal; `completed_at`; the terminal event.                                                                                                                                                                                                                   |
| Redemption, TR                     | The caller's transaction on the same connection. Identity guard for a reservation or a `link` (a `link` then reads its `domain_linked_at` by a locking read), enforcement guard, connections (for a `link`, with those holding the identity's verified domain links), applicable domain, code, links, then the application's guards. Bindings are confirmed; a voided or replayed code is refused; the code is consumed; expiry, purpose, application, connection and verifier are judged; then the common and the purpose's checks.                              |
| `sign_in` in TR                    | An existing link: continuity by its id. A reservation: every condition again for the same candidate, then activation, which clears the reservation's fields and raises `links_version`. The adapter writes its session and accepted evidence, and the sign-in is acknowledged. Together.                                                                                                                                                                                                                                                                          |
| `link` in TR                       | The current caller, freshness and eligibility; the link created, the same link passing idempotently, or provenance and suspension cleared by the confirmation. No session, no proof. Commits with the consumption.                                                                                                                                                                                                                                                                                                                                                |
| `reauthenticate` in TR             | The exact link and the active session bound to it, locked; an adapter's own result with no authentication time is refused (`authentication_expired`); the freshness write with any evidence newly accepted. Sign-in provenance and lifetime are kept. Commits with the consumption.                                                                                                                                                                                                                                                                               |
| Refusal in TR                      | After consumption, that code's reservation is deleted, by its identity and handoff reference, one failure event queues and the refusal commits, with no session and no activation. An exception rolls TR back instead.                                                                                                                                                                                                                                                                                                                                            |
| Principal widening, TW             | The application's transaction on the same connection. `Linking\ScopeWidening::widened()` first: every identity's guard, in ascending digest order; the connections holding any of their rows, in one statement; those rows; every row checked to be in a locked connection before anything changes; each active link in another tenant's connection suspended and its sessions revoked, a suspended one's revoked again, a reservation deleted. Then the application's guard and its principal write. Commits together.                                           |
| Administration and withdrawal, TA  | In the change's transaction: connection and domain locks in order; the change; affected reservations deleted (`Links\ReservationWithdrawal`); versions raised. A protocol trust change also voids unfinished requests and unredeemed codes.                                                                                                                                                                                                                                                                                                                       |

### Link and reservation states

| State                            | Transitions                                                                                                                                                                                                              |
|----------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Absent                           | to `reserved` by an eligible domain completion; to `active` by an explicit `link` or provisioning                                                                                                                        |
| Reserved                         | to `active` only by its bound successful redemption; to absent on refusal, expiry cleanup, withdrawal or invalidation. Never resolves a sign-in                                                                          |
| Active, domain provenance        | resolves while eligible; to suspended when scope fails; to active without domain provenance by a confirming `link`; kept across an explicit migration, whose relink keeps the provenance and revokes the link's sessions |
| Suspended, domain provenance     | resolves nothing; cannot provision or reserve; to active without provenance only by a confirming `link`; to absent on removal                                                                                            |
| Active, confirmed or provisioned | resolves through its exact connection, issuer and subject; to absent on removal or an explicit migration                                                                                                                 |

Expired, failed and voided reservations leave no tombstone: deletion and the handoff's immutable reservation binding
prevent resurrection, since a replacement has another reservation identity. A consumed, unfinished request has no
recovery once its in-memory continuation is lost. A suspension is latched: removing the principal later never restores
the link, and only a confirming `link` does, clearing the provenance for good. `Contracts\PrincipalScope` answering
`outside_tenant` latches it, and its resolution revokes the sessions established through the link synchronously,
transactionally and idempotently, under the established order: the principal-change transaction is the primary
revocation point and keeps revoking on an already suspended link, and this repairs what it missed. `unknown` asserts no
widening, so it refuses that attempt alone with `principal_scope_unknown`: it creates no suspension and revokes nothing,
and a link already suspended stays suspended. A contract that cannot reach its store throws instead, which refuses
nothing and latches nothing.

A confirmation must be the person's own. The identity provider behind a link of verified domain provenance can sign the
person in and renew their freshness, so it could answer a `link` of them, and clear the very provenance that holds it to
the principal scope rule. An identity holding an active or suspended such link, in any connection, therefore needs
`Contracts\LinkConfirmation` to answer `independent` before any `link` of it goes on, confirming or adding a subject;
otherwise it is `independent_authentication_required`. A session that stands on such a link in any connection is not
independent proof. So that removing the link first changes nothing, activating a reservation stamps `domain_linked_at`
on the identity's guard (`IdentityLock::recordDomainLink()`), which nothing clears; a `link` redemption reads it by a
locking read once it holds the guard (`HandoffRecheck::lock()`, carried as `RecheckLock::$domainLinkHeld`), and an
identity that has ever held such a link asks the contract even when none remains, with the ids of those it holds now,
possibly none. The contract is given the caller the redemption is made for (`Identities\Caller`), forwarded as the
application gave it after its identity is compared with the bound one, and judges that caller's session, never the
request being served: a caller with no session, or a session it cannot tie to the caller's identity or guard through the
redeemer's commit, is `dependent`. It answers by how the session was established: through a link that had verified
domain provenance then, whether held now, removed or confirmed since, is `dependent`. A subject migration that keeps a
link's provenance needs no stamp, since only an activation ever gives it. The default answers `dependent`, so someone
whose only credential is that link cannot confirm it until they hold another. Removal is not the only way out:
application-controlled recovery, or a credential established independently of the provider, qualifies. Removing the link
does not turn its surviving session into independent authentication, so credential enrolment and recovery must preserve
that distinction. `Linking\LinkConfirmationGate` reads those links by a locking read in id order, under the identity's
guard and the locks of the connections holding them, before the subject's own link and before any application contract,
in the redemption's judgement and again in its admission.

Every reservation creation, replacement, deletion and activation, and every suspension and confirmation, raises the
connection's `links_version` under its lock, so a PostgreSQL `REPEATABLE READ` transaction whose snapshot predates the
change fails to serialise rather than miss it.

### Deadlines

`handoff_expiry = reservation_expiry = min(request_expiry, issuance_time + handoff_ttl)` for a reserved flow, as stored:
`Contracts\HandoffIssuer` answers its stored expiry and an opaque reference, and `LinkReservations::bindHandoff()`
writes both in T2. A verified response stops being valid at the earlier of its request's expiry and
`sso.linking.verified_result_max_age_seconds` from when it was verified, checked in T2, before the helper's write and in
T3 (`request_expired`). No continuation extends a request's authority.

### The redemption paths

`HandoffRedemption::admit()` is the session-admission API: it needs the caller's transaction open on the storage
connection (a `LogicException` otherwise), and the session the caller writes commits with the consumption, under the
locks. `redeem()` inside such a transaction is the same. `redeem()` with none open is the standalone path, for a `link`
alone, which creates no session: it commits before it answers, and `RedemptionResult::isAdmitted()` is false. Asking it
for a `sign_in` (linked, reserved or unlinked) or a `reauthenticate` is a `LogicException` that leaves the code
unconsumed; unlinked handoffs remain available through the transactional API. A `sign_in` or `reauthenticate` code
presented where a `link` is asked for is the client's error: it is consumed and refused as `purpose_mismatch`. An
adapter redeeming its own codes calls `HandoffRecheck`'s `lock()`, naming a code's reservation and a `link`'s identity,
`admit()`, `discardReservation()` and `acknowledgeSignIn()`, with a `HandoffBinding` of what its issuer stored.

The session's authentication time is an adapter obligation: under its session lock, in the redemption's transaction, it
writes `max(current, provider_time)`, so a renewal never moves it backwards. The package does not hold the session.

Inside a caller's transaction, a retry is only ever of the whole of it; the standalone path retries only its own
transaction (`handoffs.md`). A committed refusal spends the code; a rollback undoes consumption and activation
together.

### What the application's contracts guarantee

Package locks do not serialise the application's writers unless those writers take part.

| Contract                   | Default                      | Protected through admission commit by                                                                                                                                                                                                                                                                                        |
|----------------------------|------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `LinkEmailMatcher`         | `NoEmailMatches`             | a uniqueness guarantee on the verified email, or a guard every writer of one takes. Locking the returned rows is not enough                                                                                                                                                                                                  |
| `PrincipalScope`           | `RefusingPrincipalScope`     | a widening calling `Linking\ScopeWidening` first in its transaction, whose identity guard every reservation, activation and confirmation takes; it suspends the identity's domain links and revokes the sessions established through them through `Contracts\SessionRevocation`; a guard writers of principals take after it |
| `TenantMembership`         | `NoTenantMembership`         | a guard writers of memberships take; the acceptance time is the person's, never an administrator's creation time                                                                                                                                                                                                             |
| `LinkConfirmation`         | `RefusingLinkConfirmation`   | a guard writers of sessions take; with none, or when it cannot tell, it answers `dependent`. Freshness an identity provider renewed is not the person's confirmation                                                                                                                                                         |
| `LinkEligibility`          | `RefusingLinkEligibility`    | a guard its writers take, or an acceptance that a later change does not undo the link                                                                                                                                                                                                                                        |
| `ReauthenticationSessions` | `NoReauthenticationSessions` | `lockedStanding()` locks the session's row, bound to exactly the link, through the write                                                                                                                                                                                                                                     |
| `EvidencePolicy`           | `InsufficientEvidence`       | current policy at redemption; the redeemer stores what it accepted in its transaction                                                                                                                                                                                                                                        |
| `HandoffIssuer`            | `DatabaseHandoffStore`       | binding and stored expiry written with the code; a missing reference or later expiry fails closed                                                                                                                                                                                                                            |
| `Linker`                   | `NoLinks`                    | a typed `LinkResolution`, with a link id. Whatever writes a link needs `Contracts\LinkStorage`: `LinkStore`, or a wrapper delegating to it; `NoLinks` is none, and a boot check reports it while the `domain_linking` feature is on                                                                                          |

A principal mutation calls exactly this, in its one transaction on the storage connection: `ScopeWidening::widened()`
first, given the identities it changes, which takes their guards and holds them until commit; then the application's
guard and its principal write; then it commits. A reservation, an activation or a confirmation of any of those
identities therefore runs wholly before the change, and is found by it, or wholly after, and sees the principal written.
No isolation level is required, and the application's guard never meets a package lock in the other direction.

### Custom implementations and sessions

`Contracts\LinkStorage` is the transactional link storage that resolution and mutation share: ownership (`holdings()`,
`create()`), generations (the id `resolve()` answers, another once a link is made again), reservations
(`reservations()`) and confirmation (`confirm()`, `suspend()`, `revokeSessions()`). `LinkStore` implements it and a
wrapper delegates to it. The `link` purpose, the provisioning helper and linking by a verified domain each validate the
pairing through `Links\LinkStorageBinding` and refuse before writing anything, with a `LogicException` naming the
problem, so no row is ever written that the resolver ignores; a `Linker` without it only resolves. An alternative issuer
stores reservation bindings and writes inside the completion's transaction on the same Laravel connection, or the
completion rolls back. Link suspension blocks new admission and reauthentication. Widening a person's scope also revokes
the sessions established through the affected domain links, through the adapter, in the principal-change transaction. A
provisioned identity can survive a later completion failure; that is the accepted consequence of provisioning outside
the package's locks.

That an identity offered to the provisioning helper is new is the adapter's obligation: a grant proves authority to
provision for this result, not when an application identity was created.

### Events

`ResultVerified` once per verified response. `ResultUnlinked` synchronously, with no package transaction open, the one
event that is not after commit and the one that carries the result; it refuses serialisation, so a queued listener fails
loudly. Link creation, activation (`LinkCreated` then `LinkActivated`, which never carries the provider's email as a
destination), confirmation (`LinkConfirmed`), suspension (`LinkSuspended`) and handoff events after their owning
transaction commits. `ReauthenticationCompleted` only with the committed freshness update.

### Settings

`sso.linking` caps `verified_result_max_age_seconds` (5 to 300, default 120) and `evidence_max_age_seconds` (60 to 3600,
default 900), the ceiling a connection's evidence policy may only tighten with its own `max_age_seconds`, judged against
the ceiling at write time and clamped to the ceiling as it is at read time, so lowering it later still wins.
`shared_issuers` adds to the shared issuers the package knows without ever changing one (`Linking\LinkingSettings`):
Google's and Slack's (`https://slack.com`, told apart by `https://slack.com/team_id`). Microsoft Entra's `common` and
`organizations` are tenant-independent authorities and no issuers: the real issuer of a token they lead to names its
tenant, so explicit classification applies to that issuer, which under the `microsoft_entra` preset is `shared` on
`tid`. A connection's linking settings are off by default and raise `linking_version`, which is no protocol trust
change: it deletes reservations and voids no flow. An unset issuer classification is not single organisation. A
response's accepted evidence cannot authorise a reservation once the linking version differs under the lock, and a
reservation carries the version it was made under.

## Success Path

- A linked `sign_in` finishes in T2 and its code is admitted in the caller's transaction, with the link that established
  it answered for the session to bind.
- An eligible unlinked `sign_in` reserves in T2, its handoff expiring exactly with the reservation, and its redemption
  activates the link in the transaction of the caller's session write.
- A genuinely unlinked `sign_in` stops at the boundary, is offered once to `ResultUnlinked`'s listeners with no package
  transaction open, and is finished by T3 against what the link resolves to then.
- A `link` is completed for an eligible identity, and creates the link, or confirms the one it holds, in its redemption.
- A `reauthenticate` is completed for a result resolving to its identity, and renews the session bound to exactly that
  link in its redemption.

## Failure / Edge Cases

- A suspended link is `link_suspended`, and another flow's live reservation `link_reserved`: neither reaches a
  reservation, provisioning or an unlinked handoff.
- A link of unknown scope is `principal_scope_unknown` for that attempt, in any purpose, and nothing is stored or
  revoked.
- A widening or a confirmation holding its guard makes the other wait, so neither order loses a link or a reservation.
- An identity that has held a verified domain link and removed it is still `independent_authentication_required` for a
  `link`, creating or confirming, until the contract answers `independent`; re-linking by the domain names the new link.
- A reservation gone, expired, or one of whose conditions no longer holds for that same identity is
  `reservation_invalid` at redemption, never a fallback; a different match is never the new target.
- A linking policy version that moved after validation reserves nothing, and the result goes on unlinked.
- A deadline passed in T2 or T3 is `request_expired`.
- A `reauthenticate` result with no authentication time, or one before the request less the skew, is
  `authentication_expired`, and one later than now plus the skew `assertion_expired`, in T2 and from any driver.
- An eligible identity whose guard was not taken, since the email moved between the plain read and the lock, is
  `reservation_invalid` at completion, and a subject held when read and absent under the lock is `link_changed`.
- A wrong result given to the helper spends the grant and is `grant_wrong_result`; the listener rolls its identity and
  membership transaction back, and recovery is a new flow, not reuse of that grant.
- A claim of the grant is bound to the outermost transaction on the storage connection whose callbacks apply, the
  listener's or else the helper's own (the testing traits' wrapping transaction is not one), and only while one is open,
  stepping only to a strictly lower level, so a record an unreported failed commit left behind is never it. It is given
  back to the same dispatch only when that transaction's rollback callback has run and its manager no longer holds it.
  So a listener may retry its whole transaction (`DB::transaction($work, 3)`). A commit, a refusal, a rolled-back
  savepoint inside a surviving transaction, a claim not yet bound, and a commit Laravel 12 fails without telling its
  manager leave it spent. On InnoDB at `REPEATABLE READ`, two first sign-ins can deadlock on the gap locks of their
  empty-range locking reads of a new identity's links: the listener retries, and `READ COMMITTED` for its transaction is
  recommended.
- A linker not backed by `Contracts\LinkStorage` is a `LogicException` before a write, in each path that writes a link.
- A listener's exception ends the completion as a server error: replay is recorded, `completed_at` stays unset, no
  code is issued, and nothing resumes it. A link it made stays made.
- A listener leaving a transaction open is rolled back and is a `LogicException`.
- An issuer that binds nothing, or stores a later expiry than it was given, rolls the completion back.
- The standalone path asked for any purpose but a `link` is a `LogicException`, with the code unconsumed and nothing
  recorded in the single-use store; asked for a `link` with a code of another purpose, it is `purpose_mismatch`.
- A resolution outside the package's locks that latches a suspension locks the link's connection first and the link
  again, and suspends, revokes and reports only a link still active, so two of them latch once.

## Implementation Anchors

- `src/Completion/CompletionPipeline.php`, `CompletionLocks.php`, `CompletionLock.php`, `ProvisioningOffer.php`,
  `VerifiedDeadlines.php`, `src/Completion/Rules/`, `src/Completion/Stages/CheckPurpose.php`, `DomainReservation.php`,
  `Provisioning.php`.
- `src/Links/LinkResolution.php`, `LinkReservations.php`, `ReservationTerms.php`, `ReservationWithdrawal.php`,
  `ReservedCandidate.php`, `LinkStore.php`; `src/Linking/DomainLinkEligibility.php`, `ReservationActivation.php`,
  `LinkingSettings.php`, `LinkingCheck.php`, `LinkConfirmationGate.php`, `RefusingLinkConfirmation.php`,
  `IdentityLock.php`, `LinkingDiscovery.php`, `ReservationDiscovery.php`, `ScopeWidening.php`;
  `src/Contracts/LinkStorage.php`, `src/Links/LinkStorageBinding.php`, `LinkHoldings.php`;
  `src/Models/IdentityGuard.php`; `src/Exceptions/LinkCandidatesChanged.php`; `src/Connections/LinkingPolicyReset.php`.
- `src/Handoffs/HandoffRedemption.php`, `HandoffRecheck.php`, `HandoffBinding.php`, `src/Handoffs/Redemption/`,
  `src/Contracts/PurposeBranch.php`.
- `src/Provisioning/ProvisioningGrant.php`, `ProvisioningHelper.php`, `ProvisioningResult.php`,
  `Enums/ProvisioningStatus.php`, `src/Events/ResultUnlinked.php`, `src/Evidence/AcceptedEvidence.php`.

## Authoritative Tests

- `tests/Feature/Linking/StateMachineCompletionPipelineTest.php`, on `tests/Feature/Linking/LinkingTestCase.php`.
- `tests/Feature/Linking/ProvisioningTest.php`, `ProvisioningEventSequenceTest.php`,
  `tests/Feature/Provisioning/ProvisioningHelperTest.php`, `tests/Integration/Linking/ConcurrentProvisioningTest.php`,
  `tests/Unit/Provisioning/ProvisioningGrantTest.php`, `tests/Unit/Events/ResultUnlinkedTest.php`,
  `tests/Performance/ProvisioningQueryBudgetTest.php`.
- `tests/Feature/Linking/IdentityLockTest.php`, `tests/Integration/Linking/IdentityGuardMigrationTest.php`.
- `tests/Feature/Linking/DomainLinkEligibilityTest.php`, `DomainLinkingEventSequenceTest.php`,
  `LinkingPolicyServiceTest.php`, `ReservationWithdrawalTest.php`, `ScopeWideningTest.php`,
  `LinkStorageBindingTest.php`, `tests/Integration/Linking/ConcurrentReservationTest.php`,
  `ConcurrentActivationTest.php`, `ConcurrentScopeWideningTest.php`.
- `tests/Feature/Linking/LinkConfirmationTest.php`, `IssuerChangeTest.php`, `RealProtocolLinkingTest.php`,
  `tests/Unit/Linking/LinkConfirmationContractTest.php`, `RefusingLinkConfirmationTest.php`,
  `LinkConfirmationGateTest.php`.
- `tests/Feature/Linking/LinkBranchTest.php`, `LinkAdmissionTest.php`, `LinkPurposeEventSequenceTest.php`,
  `tests/Integration/Linking/ConcurrentConfirmingLinkTest.php`.
- `tests/Feature/Linking/ReauthenticationBranchTest.php`, `ReauthenticationEventSequenceTest.php`,
  `tests/Feature/Completion/ReauthenticationRulesTest.php`,
  `tests/Integration/Linking/ConcurrentReauthenticationTest.php`.
- `tests/Integration/Combined/RedemptionRacesTest.php`, `ReservationProvisioningRacesTest.php`.
- `tests/Feature/Completion/CompletionPipelineTest.php`, `tests/Feature/Handoffs/HandoffRecheckTest.php`,
  `tests/Feature/Links/LinkStoreTest.php`.

## Change Triggers

- A stage, a transaction's writes or the lock order.
- A new link or reservation state, or a new write that a concurrent change must see, which raises `links_version`.
- A new flow that changes an identity's verified domain links, which takes its guard first.
- A contract's guarantee through admission commit.
- A new purpose, or a new session-writing redemption path.
