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
4. In a transaction on the storage connection (a savepoint inside the caller's), the code's connection row is locked
   (gone: `connection_unavailable`), then the code row is read again, locked (gone: `handoff_unknown`).
5. A code whose `voided_at` is set is `handoff_unknown`.
6. A code whose `redeemed_at` is set, or whose digest the single-use store has seen, is `replayed`.
7. The code is consumed: its digest is recorded in the single-use store until `max(expires_at, now + 1s)` and its
   `redeemed_at` set, in the transaction.
8. A code whose `expires_at` is not after now is `handoff_expired`.
9. A code of another purpose than the one asked is `purpose_mismatch` (SSO-9.9).
10. One of another application, compared exactly, is `application_mismatch`.
11. One of another connection, compared exactly, is `connection_mismatch`.
12. A verifier that is not `Verifier::isWellFormed()`, or does not satisfy the code's challenge (compared in constant
    time), is `verifier_mismatch`.
13. The result is decrypted, restored and `HandoffRecheck::recheck()`ed against the linked identity:
    `connection_unavailable`, `enforcement_unsatisfied` or `link_changed`.
14. A `sign_in` code with a linked identity calls `HandoffRecheck::acknowledgeSignIn()`.
15. `HandoffRedeemed` is reported, after commit.
16. It answers `redeemed`.

- Every refusal from step 8 on keeps the code consumed: a wrong purpose, application, connection or verifier spends
  the code, so a correct redemption after it is `replayed`. Refusals before step 7 write nothing but the attempt.
- Every read that decides the redemption is on the write connection (SSO-11.3); the two reads in step 4 are locking
  reads, so a caller's older `REPEATABLE READ` snapshot never answers whether the code is voided or redeemed. Step 3's
  read is plain: it gives only the row's id and connection, which never change, and a miss refuses (fails closed).
- The lock order is `flows.md`'s: the connection's row, then the code's. A change that voids a connection's codes
  (BL-37) locks the connection first, so it waits for a redemption that holds it, or the redemption finds the code
  voided.
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
redemption and for an adapter that redeems codes of its own (under `laravel-iam`, `laravel-authentication`'s handoff
codes, AUTH-3.10):

- `recheck(VerifiedResult $result, ?IdentityReference $linkedIdentity): Handoffs\Enums\RecheckOutcome` answers, in
  order, the first that refuses:
  1. `connection_unavailable`: the result's connection, read with `ConnectionFinder::findForUpdate()` for the result's
     tenant, is gone, of another tenant, or not usable (`ProtocolManager::isUsable()`);
  2. `enforcement_unsatisfied`: the bound `Contracts\Enforcement`, asked for the connection's tenant on the result's
     application, is not satisfied by the connection;
  3. `link_changed`: the bound `Contracts\Linker` resolves the result to another identity than the one given: a link
     removed, reassigned (another type or id, byte for byte), or added where there was none;
  4. otherwise `passed`.
- `RecheckOutcome` is `passed`, `connection_unavailable`, `enforcement_unsatisfied` or `link_changed`, and `reason()`
  answers the `FailureReason` a redemption refused by it reports, `null` for `passed`.
- `acknowledgeSignIn(VerifiedResult $result)` sets the connection's `has_completed_sign_in` (SSO-4.3), through the
  model, on the row locked for update, and writes nothing when it is already set. A result of another purpose is a
  `LogicException`, and so is a connection that is gone. The redeemer calls it after the recheck passed, for a
  `sign_in` result linked to an identity; a `link` or `reauthenticate` code, an unlinked handoff and a code issued but
  never redeemed never set the flag.
- Both run only inside a transaction open on the storage connection; with none, each is a `LogicException` (decision
  D5). An adapter writes its consumption through the same Laravel connection, inside that transaction, so the checks,
  its consumption and the acknowledgement commit or roll back together.
- The tenant's enforcement row is not locked: its lock precedes the connection's (`flows.md`). The default
  enforcement contract reads it from the write connection; inside a transaction that has made no plain read before,
  that is the state as committed now. The package's link store reads the link with a locking read.

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
2. The client posts the code and its verifier to the application's redemption endpoint, which calls `redeem()` with
   the purpose it redeems, its application and the connection.
3. The code is found, locked, consumed, checked, rechecked; a `sign_in` acknowledges the connection's completed
   sign-in; the transaction commits and `HandoffRedeemed` is reported.
4. The application signs in (or links, or re-authenticates) with the result.

## Failure / Edge Cases

- A replay, or a code the single-use store has seen, is `replayed`, and is written nothing more.
- A code at its expiry, or after, is `handoff_expired` and consumed; one a second before it is redeemed.
- A connection disabled or left incomplete since completion is `connection_unavailable` and consumes the code; one
  deleted is `connection_unavailable` at step 4 and consumes nothing.
- Enforcement turned on since completion by other connections is `enforcement_unsatisfied`.
- A link removed, reassigned or added since completion is `link_changed`.
- A redemption inside the caller's transaction that rolls back leaves the code unredeemed and reports nothing.
- A linker that throws, a corrupt stored result and a database error propagate as server errors (SSO-11.4).

## Implementation Anchors

- `src/Handoffs/DatabaseHandoffStore.php`, `src/Handoffs/HandoffRedemption.php`, `src/Handoffs/RedemptionResult.php`,
  `src/Handoffs/Enums/RedemptionStatus.php`, `src/Handoffs/HandoffRecheck.php`, `src/Handoffs/Enums/RecheckOutcome.php`,
  `src/Handoffs/HandoffEvents.php`.
- `src/Handoffs/HandoffCode.php`, `src/Handoffs/HandoffGrant.php`, `src/Handoffs/IssuedHandoff.php`,
  `src/Models/HandoffCode.php`, `src/Contracts/HandoffIssuer.php`.

## Authoritative Tests

- `tests/Unit/Handoffs/RedemptionResultTest.php`, `tests/Unit/Handoffs/RecheckOutcomeTest.php`.
- `tests/Feature/Handoffs/DatabaseHandoffStoreTest.php`: the stored row, digest only, the result encrypted.
- `tests/Feature/Handoffs/HandoffRedemptionTest.php`: each step's reason in order, consumption on a mismatch, the
  expiry boundaries, voided and seen codes, link, enforcement and connection changes, the completed-sign-in flag,
  verifier lengths, distinct kinds, the limit, corrupt results and database errors.
- `tests/Feature/Handoffs/HandoffRecheckTest.php`: each outcome and its order, no transaction, the locking read, the
  acknowledgement.
- `tests/Feature/Handoffs/RedemptionEventSequenceTest.php`, `tests/Feature/Handoffs/FullFlowTest.php`.
- `tests/Integration/Handoffs/ConcurrentRedemptionTest.php`, `tests/Integration/Handoffs/RedemptionTransactionTest.php`.
- `tests/Performance/HandoffQueryBudgetTest.php`.

## Change Triggers

- A step added to, removed from or moved in the redemption, or a change to what consumes the code.
- A change to what a code is bound to, to what the store keeps, or to how the result is encrypted.
- A change to the recheck's checks, their order, the locks they take, or the acknowledgement.
- A change to the events a redemption reports or to their context.
