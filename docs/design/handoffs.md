# Handoff Codes

## Purpose

This note records how a completed flow's verified result reaches the client that started it (SSO-9.2, SSO-9.9,
SSO-4.3, SSO-4.6, SSO-8.5, SSO-5.2): the package's own store, which issues a single-use code inside the completion's
transaction; the package's own redemption, which consumes the code atomically, checks what it is bound to, and checks
the connection, enforcement and the link again; and the recheck and acknowledgement an adapter calls when it redeems
codes of its own. The tables, the value types and the lock order are in `flows.md`; how a code is issued during a
completion is in `completion.md`.

## Invariants

### Issuing

- `Handoffs\DatabaseHandoffStore` is the default `Contracts\HandoffIssuer` (bound scoped). `issue(HandoffGrant)`
  generates a `HandoffCode` (43 base64url characters, 256 bits) and inserts one row through `Models\HandoffCode` on
  the storage connection, inside the completion's transaction; it opens none of its own, so a completion rolled back
  keeps no code (decision D5).
- The completion holds the connection's row lock when it asks, and the store raises the connection's `flows_version` by
  one under it for each code it issues, so the insert also writes the connection's row: a PostgreSQL `REPEATABLE READ`
  change whose snapshot predates the code fails to serialise when it locks the connection, rather than void the
  connection's codes without it (`Connections\InFlightVoider`, `connection-lifecycle.md`).
- The row holds `code_digest`, the lower-case hex SHA-256 of the code, never the code; `purpose`, `application`,
  `connection_id` and `request_reference`, from the result; `handoff_challenge`, the client's S256 challenge;
  `identity_type` and `identity_id` (`link`, `reauthenticate`) and `session_id` (`reauthenticate`), from the grant;
  `linked_identity_type` and `linked_identity_id`, what the result's link resolved to at completion; `result`, the
  JSON of `VerifiedResult::toArray()` encrypted through `Contracts\SecretEncrypter`; `enforcement_version` and
  `session_not_after` (SSO-9.10); `expires_at`.
- Times are kept to the whole second, so a code expires at most a second before its grant says; the returned
  `IssuedHandoff` carries the expiry as stored. The code is revealed once, on the completion's redirect, and is never
  logged or put in an event.
- A database error, a result that cannot be encoded and an encrypter that cannot encrypt propagate, which refuses the
  completion as a server error (SSO-11.4).

### Redeeming

`Handoffs\HandoffRedemption::redeem(Purpose $purpose, string $application, string $connectionId, string $code,
string $verifier)` (`@api`, resolved per request) answers a `Handoffs\RedemptionResult`. The steps run in this fixed
order, and the first that refuses ends the redemption:

1. The attempt is counted with `AttemptSubject::redemption()` against the IP address of the request being served
   (none in a console) (SSO-11.8): a full limit is `rate_limited`, with its wait.
2. A code that is not `HandoffCode::isWellFormed()` is `handoff_unknown`.
3. The row is read by `code_digest` on the write connection and matched again in constant time
   (`HandoffCode::matches()`, SSO-11.9); none is `handoff_unknown`.
4. The code's connection's tenant is read by a plain read before the transaction opens (a connection's tenant never
   changes). Then, in a transaction on the storage connection (a savepoint inside the caller's), a connection gone is
   `connection_unavailable`, and `HandoffRecheck::lock()` takes the locks of `flows.md`'s order for that tenant, the
   connection and the code's application: for a code bound to a reservation or a `link` code, the identity's guard first
   (the first statement of a standalone redemption's transaction); under `DatabaseEnforcement` with the `enforcement`
   feature on, the enforcing tenant's row (the tenant `Contracts\EnforcementInheritance` names, inserted unconfigured
   when it has none) and then, in one locking statement in ascending id order, the connection and the connections the
   rule names; otherwise the connection alone (gone meanwhile: `connection_unavailable`). Only then is the code row read
   again, locked: gone, or no longer naming the connection and the application its plain read did, it is
   `handoff_unknown`, and no other lock is taken out of order.
5. On the standalone path, asking for any purpose but a `link` is a `LogicException`, before the single-use store
   records the code or it is consumed; a code of another purpose asked for as a `link` goes on, and step 9 refuses it.
   A code whose `voided_at` is set is `handoff_unknown`.
6. A code whose `redeemed_at` is set, or whose digest the single-use store has seen, is `replayed`.
7. The code is consumed: its digest is recorded in the single-use store until `max(expires_at, now + 1s)` and its
   `redeemed_at` set, in the transaction.
8. A code whose `expires_at` is not after now is `handoff_expired`.
9. A code of another purpose than the one asked is `purpose_mismatch` (SSO-9.9).
10. One of another application, compared exactly, is `application_mismatch`.
11. One of another connection, compared exactly, is `connection_mismatch`.
12. A verifier that is not `Verifier::isWellFormed()`, or does not satisfy the code's challenge (compared in constant
    time), is `verifier_mismatch`.
13. The result is decrypted, restored (a result naming another tenant than its connection's is not one the package
    wrote) and `HandoffRecheck::recheck()`ed against the linked identity under step 4's lock:
    `connection_unavailable`, `enforcement_unsatisfied` or a purpose's own refusal (`linking.md`).
14. A `sign_in` code with a linked identity calls `HandoffRecheck::acknowledgeSignIn()` under the same lock.
15. `HandoffRedeemed` is reported, after commit.
16. It answers `redeemed`.

- Every refusal from step 8 on keeps the code consumed: a wrong purpose, application, connection or verifier spends
  the code, so a correct redemption after it is `replayed`. Refusals before step 7 write nothing but the attempt.
- Every read that decides the redemption is on the write connection (SSO-11.3); the reads under step 4's locks are
  locking reads, so a caller's older `REPEATABLE READ` snapshot never answers whether the rule is on, the connection
  usable, or the code voided or redeemed. Step 3's read and the read of the tenant are plain: they give only the row's
  id, connection and application and the connection's tenant, which the locked reads confirm, and a miss refuses
  (fails closed). Both run before the redemption's transaction opens, so on the standalone path the identity guard of a
  `link` is that transaction's first statement, and every plain read after it, under MySQL's `REPEATABLE READ`, sees
  what the guard's previous holder committed. A standalone `link` that comes to `Exceptions\LinkCandidatesChanged` all
  the same is rolled back and restarted once; inside a caller's transaction it propagates for a retry of the whole.
- A `link` redemption reads, by a locking read under the identity's guard, whether the identity has ever held an active
  link by a verified domain (`domain_linked_at`, stamped at activation and never cleared), and asks
  `Contracts\LinkConfirmation` whenever it has, even when none remains.
- The standalone path refuses any purpose asked for but a `link` with a `LogicException` as soon as the code is locked,
  before the single-use store records it and before it is consumed, so a store that is not transactional keeps nothing
  either. The purpose asked for decides, not the code's: a `sign_in` or `reauthenticate` code posted to a `link`
  endpoint is the client's error, consumed and refused as `purpose_mismatch`, never a server error.
- The lock order is `flows.md`'s: for a code bound to a reservation and a `link` code, the identity's guard, then the
  tenant's enforcement row, then connection rows in id order, then the code's. A change that voids a connection's codes
  (BL-37) locks the connection first, so it waits for a redemption that holds it, or the redemption finds the code
  voided. A change to enforcement locks the rule's row first, so it waits for a redemption that holds it, and its
  revocation, inside its own transaction, then sees the session the redeemer wrote in its transaction; or the redemption
  waits for the change and refuses under the new rule. No session written in the redeemer's transaction survives a rule
  that does not allow it.
- On PostgreSQL under `REPEATABLE READ`, a redemption that waited on a change of the rule may get a serialisation
  failure (SQLSTATE `40001`) instead of the new rule. It propagates, as a server error; the package never retries a
  part of a caller's transaction, and a caller that redeems inside its own transaction retries the whole of it.
- Racing redemptions of one code serialise on the connection's lock, and the code's `redeemed_at` and the single-use
  record are written in the same transaction, so exactly one redeems it, plain or inside the racers' own transactions.
- A code, a request's public reference and a verifier are distinct kinds (`HandoffCode`, `RequestReference`,
  `Verifier`): a reference or a digest is never well formed as a code, a challenge or a verifier presented as a code
  matches no digest, and a code or a challenge presented as a verifier satisfies no challenge.
- The single-use namespace is `handoff_code` (`HandoffRedemption::NAMESPACE`), keyed by the code's digest.

### The result

- `Handoffs\RedemptionResult` is `final readonly`: `redeemed(result, linkedIdentity, identity, sessionId,
  enforcementVersion, sessionNotAfter)`, `refused(reason)` (never `rate_limited`) and `rateLimited(retryAfter)` (at
  least a second). Its outcome is its `status`, a `Handoffs\Enums\RedemptionStatus` (`redeemed`, `refused` or
  `rate_limited`), set by the named constructor; `isRedeemed()`, `isRefused()` and `isRateLimited()` say which. A
  refused one names its `reason`, and a rate limited one `rate_limited` with its `retryAfter`.
- It holds the verified result, which carries personal data: a dump and `json_encode()` show only `status`, `reason`,
  `retry_after`, `purpose`, `connection_id` and `request_reference`, never the subject or an attribute, and it refuses
  to be serialised or unserialised. The result itself stays serialisable (SSO-8.1).
- The restored result must name the code's purpose, application, connection and reference exactly. A stored result
  that is not JSON of a result, or names another, is an `UnexpectedValueException`; it, a ciphertext no key decrypts,
  a database error and a contract's exception propagate, roll the transaction back and leave the code unconsumed.

### The recheck

`Handoffs\HandoffRecheck` (`@api`, resolved per request) is what every redemption checks again, for the package's own
redemption and for an application that issues and redeems codes of its own. Under `laravel-iam` there are none: the
package issues, stores and redeems every handoff code (the reconciliation of AUTH-3.10 recorded as SSO-9.2/f), and the
adapter redeems through `HandoffRedemption` (`docs/guides/integrating-with-laravel-iam.md`):

- `lock(string $tenantId, string $connectionId, string $application): Handoffs\RecheckLock` comes first, before the
  redeemer locks its own code. Under `DatabaseEnforcement` with the `enforcement` feature on it calls
  `DatabaseEnforcement::lock()`: the inheritance contract names the enforcing tenant, `Enforcement\EnforcementLock`
  upserts and locks that tenant's row, and the connection and the rule's connections are locked in one statement in
  ascending id order. Otherwise (feature off, or another contract bound) it locks the connection alone with
  `ConnectionFinder::findForUpdate()`, with no enforcement statement and no inheritance call. The `RecheckLock`
  (`@api`, made only by `lock()`) holds the tenant, connection and application it was taken for, the connection's
  locked row (`null` when gone or of another tenant) and the locked enforcement; it is good only for the transaction it
  was taken in.
- `recheck(VerifiedResult $result, ?IdentityReference $linkedIdentity, RecheckLock $lock):
  Handoffs\Enums\RecheckOutcome` takes the lock (one taken for another tenant, connection or application than the
  result's is a `LogicException`), so the check is never reached without the locks, and answers, in order, the first
  that refuses:
  1. `connection_unavailable`: the connection's locked row is gone, of another tenant, or not usable
     (`ProtocolManager::isUsable()`), or the inheritance contract, asked again, no longer names the enforcing tenant
     whose rule is locked (another tenant's rule is never locked out of order);
  2. `enforcement_unsatisfied`: the enforcement of the connection's tenant on the result's application is not satisfied
     by the connection: judged from the locked rows under `DatabaseEnforcement`, asked of the bound contract now
     otherwise;
  3. the purpose's own rules (`Contracts\PurposeBranch`, `linking.md`), which compare the link as it is now with the one
     observed at completion by its id, so a link removed and made again is told apart.
- `RecheckOutcome` is `passed`, or a refusal of the same value as its `FailureReason`, and `reason()`
  answers the `FailureReason` a redemption refused by it reports, `null` for `passed`.
- `acknowledgeSignIn(VerifiedResult $result, RecheckLock $lock)` sets the connection's `has_completed_sign_in`
  (SSO-4.3), through the model, on the row the lock holds, and writes nothing when it is already set. A result of
  another purpose is a `LogicException`, and so is a connection that is gone. The redeemer calls it after the recheck
  passed, for a `sign_in` result linked to an identity; a `link` or `reauthenticate` code, an unlinked handoff and a
  code issued but never redeemed never set the flag.
- All three run only inside a transaction open on the storage connection; with none, each is a `LogicException`
  (decision D5). An adapter writes its consumption and its session through the same Laravel connection, inside that
  transaction, so the locks, the checks, its consumption, the acknowledgement and the session commit or roll back
  together. The package's link store reads the link with a locking read.
- A bound `Contracts\Enforcement` other than `DatabaseEnforcement` is asked at the recheck, under the connection's lock
  alone. A current read alone does not keep a session from escaping a change: such a contract must itself serialise
  the admission against changes to its rule until the session's transaction commits, and its revocation must find
  sessions with current reads. A bound `Contracts\EnforcementInheritance` is asked inside the redeemer's transaction,
  before the locks and again at the recheck, and must answer in a way that is safe there: from state that does not
  change under the transaction, or with a current read.

### Events

`Handoffs\HandoffEvents` reports through `Events\EventContexts` and `Events\AfterCommitDispatcher`:

- redeemed: `HandoffRedeemed`;
- refused: exactly one `FlowFailed(Flow::REDEMPTION, $reason)`, a full limit included.

Before a code is found, the context names only the purpose asked. Once found, it names the code's connection,
application, purpose and `request_reference`, the identity (the flow's for `link` and `reauthenticate`, the linked
one for `sign_in`) and the session of a `reauthenticate`; once the connection's row was read, its tenant and protocol.
Never the code, its digest, the verifier, the challenge, the subject or an attribute. Inside the redemption's
transaction the events wait for its commit, and inside a caller's transaction for the caller's; a rollback reports
nothing (SSO-10.5).

## Success Path

1. The completion issues a code through the store, under the connection's lock, and redirects with it.
2. The client posts the code and its verifier to the application's redemption endpoint, which calls `admit()` inside its
   transaction with the purpose it redeems, its application and the connection.
3. The code is found, locked, consumed, checked, rechecked; a `sign_in` acknowledges the connection's completed
   sign-in; the transaction commits and `HandoffRedeemed` is reported.
4. The application signs in (or links, or re-authenticates) with the result.

## Failure / Edge Cases

- `redeem()` with no transaction open on the storage connection redeems only a `link`, which creates no session.
  Asking it for a `sign_in`, linked, reserved or unlinked, or a `reauthenticate` is a `LogicException` there, leaving
  the code unconsumed, since each must commit with the session the caller writes. Unlinked handoffs remain available
  through `admit()`. A `sign_in` or `reauthenticate` code presented to it as a `link` is `purpose_mismatch`, and spent.
- A replay, or a code the single-use store has seen, is `replayed`, and is written nothing more.
- A code at its expiry, or after, is `handoff_expired` and consumed; one a second before it is redeemed.
- A connection disabled or left incomplete since completion is `connection_unavailable` and consumes the code; one
  deleted is `connection_unavailable` at step 4 and consumes nothing.
- Enforcement turned on since completion by other connections is `enforcement_unsatisfied`. Turned on while the
  redemption runs, it either waits for the redemption's transaction, whose session its revocation then removes, or
  is seen by it, and the redemption is `enforcement_unsatisfied`; a serialisation failure on PostgreSQL propagates.
- An inheritance contract that names another enforcing tenant at the recheck than at the lock is
  `connection_unavailable`.
- A link removed, reassigned or added since completion is `link_changed`.
- A redemption inside the caller's transaction that rolls back leaves the code unredeemed and reports nothing.
- A linker that throws, a corrupt stored result and a database error propagate as server errors (SSO-11.4).

## Implementation Anchors

- `src/Handoffs/DatabaseHandoffStore.php`, `src/Handoffs/HandoffRedemption.php`, `src/Handoffs/RedemptionResult.php`,
  `src/Handoffs/Enums/RedemptionStatus.php`, `src/Handoffs/HandoffRecheck.php`, `src/Handoffs/RecheckLock.php`,
  `src/Handoffs/Enums/RecheckOutcome.php`, `src/Handoffs/HandoffEvents.php`.
- `src/Enforcement/DatabaseEnforcement.php` (`lock()`), `src/Enforcement/EnforcementLock.php`,
  `src/Enforcement/LockedEnforcement.php`.
- `src/Handoffs/HandoffCode.php`, `src/Handoffs/HandoffGrant.php`, `src/Handoffs/IssuedHandoff.php`,
  `src/Models/HandoffCode.php`, `src/Contracts/HandoffIssuer.php`.

## Authoritative Tests

- `tests/Unit/Handoffs/RedemptionResultTest.php`, `tests/Unit/Handoffs/RecheckOutcomeTest.php`.
- `tests/Feature/Handoffs/DatabaseHandoffStoreTest.php`: the stored row, digest only, the result encrypted.
- `tests/Feature/Handoffs/HandoffRedemptionTest.php`: each step's reason in order, consumption on a mismatch, the
  expiry boundaries, voided and seen codes, link, enforcement and connection changes, the completed-sign-in flag,
  verifier lengths, distinct kinds, the limit, corrupt results and database errors, the standalone path's refusal of a
  `sign_in` or `reauthenticate` asked for, and its `purpose_mismatch` for such a code asked for as a `link`.
- `tests/Feature/Handoffs/HandoffRecheckTest.php`: each outcome and its order, no transaction, another result's lock,
  the lock order (enforcement, then connections in id order) with the feature on and nothing of enforcement with it
  off or another contract bound, an enforcing tenant that moved, the acknowledgement.
- `tests/Integration/Enforcement/EnforcementAdmissionRaceTest.php`: a redemption that writes a session racing an
  enforcement change, in both orders, with a stored rule and none, plain and inside a transaction that read first.
- `tests/Feature/Handoffs/RedemptionEventSequenceTest.php`, `tests/Feature/Handoffs/FullFlowTest.php`.
- `tests/Integration/Handoffs/ConcurrentRedemptionTest.php`, `tests/Integration/Handoffs/RedemptionTransactionTest.php`.
- `tests/Performance/HandoffQueryBudgetTest.php`.

## Change Triggers

- A step added to, removed from or moved in the redemption, or a change to what consumes the code.
- A change to what a code is bound to, to what the store keeps, or to how the result is encrypted.
- A change to the recheck's checks, their order, the locks they take, or the acknowledgement; a change to what a
  custom enforcement or inheritance contract must guarantee.
- A change to the events a redemption reports or to their context.
