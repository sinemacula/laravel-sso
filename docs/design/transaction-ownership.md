# Transaction Ownership

## Purpose

This note records which transaction owns which writes and which events, across a whole completion, redemption and
administrative change (SSO-4.5, SSO-8.8, SSO-9.9, SSO-10.5). "A failure rolls everything back" is not true of a flow
that spans several transactions, so no guarantee here is stated of a flow: each is stated of the one transaction it
belongs to. A failure undoes that transaction's writes and after-commit events, and what an earlier transaction
committed stands, by design. `linking.md` describes the stages, and this note what each stage's failure leaves.

## Invariants

- No write and no after-commit event of a transaction that rolled back survives. Whatever an earlier transaction
  committed stays, and its events have been reported.
- Every package event but one waits for the commit of the innermost transaction open on its connection, through
  `Events\AfterCommitDispatcher`, and goes with it on a rollback, a savepoint's included. `ResultUnlinked` alone is
  synchronous, with no package transaction open.
- A failed commit is a rollback: the events waiting on it are dropped, those of a savepoint that committed inside it
  included, whether the transaction is the package's or the application's own outermost one on the storage connection.
  When the commit of `transaction()` fails, Laravel 12 leaves their callbacks pending, to run on the next outermost
  commit on the connection, perhaps in another request; `AfterCommitDispatcher` drops each one whose record the next
  outermost begin marked as stranded (`Events\StrandedTransactions`). So no Laravel version reports a rolled-back change
  while that begin is observed; the cases that escape it are in `event-model.md`. A failed manual `commit()` leaves the
  connection at level 1, for the caller to roll back.
- An adapter that writes through the storage connection, inside the transaction the package has open or that it opened
  itself, commits or rolls back with it. One that writes through another connection is not atomic with it. So
  `SessionRevocation`, `ReauthenticationSessions`, a session written after `admit()`, and a listener's identity written
  in TP are each owned by the transaction they run in.

### Who owns what

| Transaction                              | Owner, and when it opens                                                          | Its writes                                                                                                                                                           | Its events                                                          | What stands when it rolls back                                                                                                 |
|------------------------------------------|-----------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|
| T1, consumption                          | The package, before validation                                                    | The request's single-use record and `consumed_at`                                                                                                                    | None                                                                | Nothing of the flow's; the request is unconsumed and may be answered again                                                     |
| T2, preparation that finishes            | The package, after validation and discovery                                       | The identity guard, the replay record, a reservation and its binding, the code, `links_version`, `flows_version`, `completed_at`, a latched suspension               | `ResultVerified`, `LinkSuspended`, `HandoffIssued`, or `FlowFailed` | T1: the request stays consumed, and a second answer is `request_unknown`                                                       |
| T2, preparation stopping at the boundary | The package, after validation and discovery                                       | The replay record and `verified_at`                                                                                                                                  | `ResultVerified`                                                    | T1; the result is never offered                                                                                                |
| None: the offer                          | No transaction open                                                               | Nothing of the package's                                                                                                                                             | `ResultUnlinked`, synchronously, and never again                    | Not applicable                                                                                                                 |
| TP, provisioning                         | The listener                                                                      | The application's identity and membership, the active link, `links_version`                                                                                          | `LinkCreated`                                                       | T1, T2, `ResultVerified` and `ResultUnlinked`. T3 does not run: no code, and `completed_at` stays unset                        |
| T3, final continuation                   | The package, after the offer                                                      | The code, `flows_version`, `completed_at`, a latched suspension                                                                                                      | `HandoffIssued` or `FlowFailed`                                     | T1, T2, `ResultVerified`, `ResultUnlinked`, and TP whole: the identity, the link and `LinkCreated`                             |
| TR, `sign_in`                            | The caller; `admit()` needs it open                                               | The identity guard and its stamp, the single-use record, `redeemed_at`, the activation, `links_version`, the acknowledgement, the application's session and evidence | `LinkCreated`, `LinkActivated`, `HandoffRedeemed`                   | Nothing of the redemption's; the code is unspent, and only the caller's whole transaction is retried                           |
| TR, `link`                               | The caller; or the package's own, standalone                                      | The identity guard, the single-use record, `redeemed_at`, the link created or confirmed, `links_version`                                                             | `LinkCreated` or `LinkConfirmed`, `HandoffRedeemed`                 | As `sign_in`. An attempt a standalone `link` counted before its transaction opened is committed, and stays                     |
| TR, `reauthenticate`                     | The caller; `admit()` needs it open                                               | The single-use record, `redeemed_at`, the session's freshness and evidence through the adapter                                                                       | `HandoffRedeemed`, `ReauthenticationCompleted`                      | As `sign_in`                                                                                                                   |
| TR that refuses                          | As the purpose's                                                                  | The single-use record, `redeemed_at`, the deletion of that code's reservation, `links_version`                                                                       | `FlowFailed`                                                        | As `sign_in`: the reservation stands and the code is unspent. A refusal that commits spends the code                           |
| TW, principal widening                   | The application                                                                   | The identity's guard, suspensions and their revocations, reservations deleted, `links_version`, the application's principal                                          | `LinkSuspended`                                                     | Nothing of the change's; the next resolution still judges the scope                                                            |
| TA, disable                              | The package, a savepoint inside the caller's                                      | `enabled`, what it voids, `trust_version`, reservations deleted, `links_version`, the revocation                                                                     | `ConnectionDisabled`                                                | Nothing of the change's                                                                                                        |
| TA, delete                               | The package, a savepoint inside the caller's                                      | Everything of the connection's, what it voids, the revocation                                                                                                        | `ConnectionDeleted`                                                 | Nothing of the change's                                                                                                        |
| TA, trust change                         | The package, a savepoint inside the caller's                                      | The setting or the certificate, what it voids, `trust_version`, reservations deleted, `links_version`                                                                | `ConnectionUpdated` or `KeyRetired`                                 | Nothing of the change's                                                                                                        |
| TA, enforcement change                   | The package, a savepoint inside the caller's                                      | The rule, the unconfigured row it may insert, the revocation                                                                                                         | `EnforcementChanged`                                                | Nothing of the change's; a rule in force stays                                                                                 |
| TA, link removal                         | The package, a savepoint inside the caller's                                      | The link, `links_version`, the revocation                                                                                                                            | `LinkRemoved`                                                       | Nothing of the change's                                                                                                        |
| Recheck's lease                          | The package, before the lookup                                                    | `recheck_leased_until`                                                                                                                                               | None                                                                | Nothing of the recheck's                                                                                                       |
| TA, recheck's result, a lapse among them | The package, after the lookup                                                     | The claim's state, reservations deleted, `links_version`                                                                                                             | `DomainLapsed`, `DomainRecheckFailed` or `DomainRestored`           | The lease, which runs out by itself: the claim stays verified and the reservation stands                                       |
| A pruning batch                          | The package, one per batch; a caller's transaction is refused                     | The rows the batch deleted                                                                                                                                           | None                                                                | Every batch committed before it, which the report counts                                                                       |
| A pruning batch of reservations          | The package, one per connection in the batch                                      | The reservations deleted, `links_version`                                                                                                                            | None                                                                | As a batch                                                                                                                     |
| Expiry claim                             | The package, one per key; a caller's transaction is refused                       | `expiry_claimed_until`                                                                                                                                               | None                                                                | Earlier keys                                                                                                                   |
| None: the warning                        | No transaction open                                                               | The marker and the release, one statement each, after the dispatch                                                                                                   | `KeyNearingExpiry`, before its marker                               | A marker statement that fails leaves the warning sent and unrecorded, so a later run sends it again once the claim has run out |
| None: the counters                       | Each statement by itself; the storage connection's transaction when they share it | The count                                                                                                                                                            | None                                                                | On a connection of their own, the count survives another transaction's rollback; on the storage connection, it goes with it    |

## Success Path

1. A reserved `sign_in` commits T1, then T2 with its reservation and code, reporting `ResultVerified` and
   `HandoffIssued`.
2. An unlinked `sign_in` commits T1 and T2, reports `ResultVerified`, offers the result, and commits TP in the listener;
   `LinkCreated` is reported. T3 then commits the code and reports `HandoffIssued`.
3. A redemption commits in the caller's TR with the session the caller wrote, reporting what its purpose reports.
4. A change commits in its TA with its revocation, reporting once.

## Failure / Edge Cases

- T2 fails, before or after its mutations, or at its commit: the request stays consumed and nothing is reported, not
  even `ResultVerified`, which waits for that commit. The second answer to it is `request_unknown`.
- A handoff issuer that throws, having written its code or not, rolls back whichever of T2 and T3 asked it, and any
  reservation it was to bind.
- TP fails: its link, identity and `LinkCreated` go. `ResultVerified` and `ResultUnlinked` stay reported. The grant is
  closed, the completion is a server error, and nothing resumes it.
- T3 fails after TP committed: the link stands, reported, with no code. That is the accepted consequence of provisioning
  outside the package's locks (`linking.md`). The person signs in again, and the link resolves.
- TR fails anywhere, the commit included: the code is unspent, the reservation stands, and the caller's whole
  transaction may be retried. A contract's exception after an activation undoes the activation.
- A standalone `link`'s TR that the database rolls back as a deadlock, a lock wait timeout or a serialisation failure
  is tried again by the package, at most three times in all; the attempt counted before TR opened is counted once.
- A refusal in TR commits, with the code spent and its reservation deleted; a failure in that commit undoes all three,
  and no `FlowFailed` is reported.
- A lapse that fails keeps its reservations and its claim verified. Its lease stands, so the next recheck takes the
  claim once the lease has run out.
- A pruning run keeps every batch that committed, and throws once the other kinds have had their turn.
- A warning is sent before its marker is written. A reporter stopped between the two has sent a warning a later run
  sends again, and a duplicate is possible where a silent loss is not.

## Implementation Anchors

- `src/Events/AfterCommitDispatcher.php`, `src/Events/StrandedTransactions.php`.
- `src/Completion/CompletionPipeline.php`, `src/Completion/ProvisioningOffer.php`,
  `src/Provisioning/ProvisioningHelper.php`.
- `src/Handoffs/HandoffRedemption.php`, `src/Handoffs/HandoffRecheck.php`.
- `src/Connections/ConnectionLifecycle.php`, `src/Connections/InFlightVoider.php`,
  `src/Enforcement/EnforcementService.php`, `src/Keys/KeyService.php`, `src/Links/LinkService.php`,
  `src/Linking/ScopeWidening.php`, `src/Domains/DomainRechecker.php`.
- `src/Pruning/PruneTarget.php`, `src/Links/ReservationWithdrawal.php`, `src/Keys/ExpiryNotifier.php`.

## Authoritative Tests

- `tests/Integration/Combined/CompletionRollbackTest.php`
- `tests/Integration/Combined/RedemptionRollbackTest.php`
- `tests/Integration/Combined/AdministrationRollbackTest.php`
- `tests/Integration/Events/AfterCommitDispatchTest.php`
- `tests/Integration/Combined/RedemptionRacesTest.php`
- `tests/Integration/Combined/ReservationProvisioningRacesTest.php`
- `tests/Integration/Pruning/PruningRacesTest.php`
- `tests/Integration/Keys/ExpiryReporterRacesTest.php`
- `tests/Integration/Completion/CompletionTransactionTest.php`,
  `tests/Integration/Handoffs/RedemptionTransactionTest.php`,
  `tests/Integration/Connections/LifecycleRevocationTransactionTest.php`,
  `tests/Integration/Enforcement/EnforcementRevocationTransactionTest.php`,
  `tests/Integration/Links/LinkRemovalTransactionTest.php`,
  `tests/Integration/SingleUse/SingleUseStoreTransactionTest.php`.

## Change Triggers

Update this note when a stage moves a write from one transaction to another, when a new transaction or adapter write
joins a flow, when an event is reported from a different transaction, or when something new is committed outside the
transaction it reports on.
