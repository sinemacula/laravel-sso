# Redeeming a Handoff

A completed flow ends with a redirect to your application's redirect URI carrying a single-use handoff code and the
request's public reference. Your client then exchanges the code, with the verifier it started the flow with, at a
redemption endpoint of your API, which answers with whatever your application signs people in with. The package's
redemption helper does the checking; your application owns the route, the session and the response.

<!-- snippet: tests/Integration/Examples/RedeemingAHandoff/redemptions/link.php#redemption-helper -->
```php
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;

$redemptions = app(HandoffRedemption::class);
```

Resolve the helper from the container for each request: it reads the request being served (for its IP address) and
keeps nothing of one request for the next.

## The route

The package registers no route. The client posts the code and its verifier in the request body, never in the URL, so
neither reaches an access log, a proxy or the browser's history:

```text
POST /api/auth/sessions
Content-Type: application/json

{"application": "web", "connection": "<the connection it started through>", "code": "<the code from the redirect>",
 "verifier": "<the verifier the client kept>"}
```

That is the sign-in route of [An example application](example-application.md#the-routes), in `routes/api.php` under
Laravel's `/api` prefix; a `link` and a `reauthenticate` code each have an authenticated route of their own, so the
endpoint, never the body, fixes the purpose.

The controller, say `App\Http\Controllers\SsoHandoffController`, is a `final readonly` class that imports
`Illuminate\Http\JsonResponse`, `Illuminate\Http\Request` and `Illuminate\Support\Facades\DB` and, from
`SineMacula\Laravel\Sso`, `Database\StorageConnection`, `Events\Enums\FailureReason`, `Flows\Enums\Purpose` and
`Handoffs\HandoffRedemption`. Its constructor takes the redemption helper as `$redemptions` and your own sign-ins as
`$signIns`: `start()` writes a session for an identity, bound to the link it resolved through, and `token()` issues the
session's credential. Its sign-in action:

<!-- snippet: tests/Integration/Examples/RedeemingAHandoff/SsoHandoffController.php#handoff-controller -->
```php
/**
 * `POST /api/auth/sessions`: redeem a sign-in handoff.
 *
 * @param  \Illuminate\Http\Request  $request
 * @return \Illuminate\Http\JsonResponse
 *
 * @throws \Throwable
 */
public function signIn(Request $request): JsonResponse
{
    [$result, $sessionId] = DB::connection(StorageConnection::name())->transaction(function () use ($request): array {
        $result = $this->redemptions->admit(
            Purpose::SIGN_IN,
            'web',                                    // your application's name, as configured
            $request->string('connection')->value(),  // the connection the client started through
            $request->string('code')->value(),
            $request->string('verifier')->value(),
        );

        // Sign in the identity the code's link resolved to, never past the
        // session's latest end and with how it began, in this same
        // transaction; an unlinked handoff names none
        $sessionId = $result->isAdmitted() && $result->linkedIdentity !== null
            ? $this->signIns->start($result->linkedIdentity, (string) $result->linkId, $result->sessionNotAfter, $result->provenance)
            : null;

        return [$result, $sessionId];
    });

    if ($result->isRateLimited()) {
        return response()->json(['error' => 'rate_limited'], 429, [
            'Retry-After'   => (string) $result->retryAfter,
            'Cache-Control' => 'no-store',
        ]);
    }

    if ($sessionId === null) {
        return response()->json(['error' => ($result->reason ?? FailureReason::UNLINKED)->value], 400, ['Cache-Control' => 'no-store']);
    }

    // Only now, after the commit, does your token leave
    return response()->json(['token' => $this->signIns->token($sessionId)], 200, ['Cache-Control' => 'no-store']);
}
```

Send every answer with `Cache-Control: no-store` (SSO-9.8): the request carried a verifier and a code, and the
response carries your application's credentials. Never echo the code or the verifier back.

The purpose is your endpoint's, never the request's: a sign-in endpoint redeems `Purpose::SIGN_IN` codes only, and a
`link` or `reauthenticate` code presented there is refused (SSO-9.9). Give each purpose its own endpoint.

Under `laravel-iam`, its adapter is the code in the transaction: it calls `admit()`, then `laravel-authentication`'s
external sign-in once, in the same transaction, and may answer a pending session. See
[Integrating with `laravel-iam`](integrating-with-laravel-iam.md#sign-in).

## `admit()` or `redeem()`

There are two ways in, and they differ only in what protects your own writes:

| Call                               | Transaction                        | `isAdmitted()` | For                                                                              |
|------------------------------------|------------------------------------|----------------|----------------------------------------------------------------------------------|
| `admit()`                          | Yours, required                    | `true`         | Anything that writes a session: it commits with the consumption, under the locks |
| `redeem()` inside your transaction | Yours                              | `true`         | The same as `admit()`                                                            |
| `redeem()` with none open          | Its own, committed when it returns | `false`        | A `link` alone, which creates no session                                         |

`admit()` is the session-admission API. With no transaction open on the package's storage connection it throws a
`LogicException` before the code is touched. Use it for every sign-in: a result that answers `isAdmitted()` false has
already committed and released its locks, so a session written from it would be protected by nothing. So every `sign_in`
code, linked, reserved or unlinked, and every `reauthenticate` code, must commit with your session write, and asking
the standalone path for either purpose is a `LogicException` that leaves the code unconsumed, and unrecorded in the
single-use store, so redeeming it again through `admit()` works. An unlinked handoff is redeemed through `admit()` like
any other, whether or not you go on to write a session. The purpose your endpoint asks for decides: a client that posts
a sign-in code to your `link` endpoint gets `purpose_mismatch`, never a server error, and the code is spent.

Both take the caller your application has authenticated as their last argument, an `IdentityReference`:

<!-- snippet: tests/Integration/Examples/RedeemingAHandoff/redemptions/link.php#admit-link -->
```php
$result = $redemptions->admit(Purpose::LINK, 'web', $connectionId, $code, $verifier, $caller);
```

Only a `link` reads it: holding a code and its verifier proves which client started the flow, not who is calling now.
No caller, or any other than the identity the code is bound to, compared byte for byte, is `identity_mismatch`. See
[Links](links.md).

## What a redemption checks

In this order, the first that fails refusing it:

1. The redemption is counted against the client's IP address (`sso.rate_limits.redemption.per_ip`).
2. The code must be a code (43 base64url characters) the package's store issued and has not voided. A reference, a
   verifier or a digest is never accepted as one.
3. A code redeemed before is a replay.
4. The code is consumed now, in a transaction, so racing requests redeem it exactly once. From here on, a refused
   redemption still spends the code: the client must start again.
5. The code must not have expired (`handoff_ttl_seconds`, 60 by default).
6. It must have been issued for the purpose, the application and the connection given, compared exactly.
7. The verifier must be the one whose S256 challenge the flow was started with, so only the client that started the
   flow can redeem its code (SSO-5.2).
8. The connection must still be enabled and complete, and still satisfy its tenant's enforcement.
9. The purpose's own rules must hold, and its writes are made:
   - `sign_in`: the same link, by its id, resolves as at completion, or the reservation the code is bound to is judged
     again for that same identity and activated;
   - `link`: the caller, freshness, eligibility and the link's continuity ([Links](links.md)), and the link is created
     or confirmed;
   - `reauthenticate`: the session is active and bound to exactly this link, and its authentication time is renewed
     ([Re-authenticating](reauthenticating.md)).

Before the code is locked, the redemption locks the tenant's enforcement (with the `enforcement` feature on and the
package's default enforcement contract bound), then the connection and the connections the rule names. A change to
enforcement made at the same time therefore either finishes first, and the redemption sees the new rule, or waits for
the redemption's transaction to end, and its session revocation then sees the session you created in it. Either way, no
session survives that the rule now in force does not allow. A tenant that never had a rule has an empty row inserted to
lock, which reads exactly as no rule.

A redeemed `sign_in` code that resolved to an identity records that the connection has completed a sign-in, which
enforcement needs before it can be turned on for the tenant (SSO-4.3). A `link` or `reauthenticate` code, an unlinked
handoff and a code that was never redeemed never do.

## The results

| Result       | When                                 | Your response                               |
|--------------|--------------------------------------|---------------------------------------------|
| redeemed     | every check passed                   | sign in, or confirm the link or the renewal |
| refused      | a check failed, for its `reason`     | a `400` with the code                       |
| rate limited | the limit for the IP address is full | a `429` with `Retry-After`                  |

A redeemed result carries:

- `result`: the `VerifiedResult` (issuer, subject, connection, tenant, protocol, application, purpose, reference, the
  mapped attributes and the provider's authentication context);
- `linkedIdentity`: the identity the result's link resolved to at completion, and still resolves to; `null` for an
  unlinked handoff, whose identity your application resolves itself (never from the email or another attribute);
- `identity`: the identity a `link` or `reauthenticate` flow was started for, and `sessionId` the session a
  `reauthenticate` flow was started on;
- `enforcementVersion`: the version of the enforcement the redemption judged under its locks (not the one the
  completion checked, which a rule change may since have replaced), and `sessionNotAfter`, the latest end of your
  session the provider's deadline sets. Keep both on the session you create (SSO-9.10);
- `linkId`: the link the identity resolved through, which your session keeps, since a `reauthenticate` accepts only the
  link that established it;
- `evidence`: what your `EvidencePolicy` accepted of the result's own assertion, for a `sign_in` or a `reauthenticate`
  ([Evidence](evidence.md));
  never for a `link`;
- `provenance`: for an admitted `sign_in` only, the session provenance captured from this redemption, which you write
  with the session once and later project into the `sso.*` authentication context keys
  ([Session Provenance](session-provenance.md)); `null` for any other purpose;
- `isAdmitted()`: whether it was redeemed inside your transaction.

A refused result carries one of these codes:

| Code                                  | Why                                                                                          |
|---------------------------------------|----------------------------------------------------------------------------------------------|
| `handoff_unknown`                     | not a code, never issued, or voided by a change to its connection                            |
| `replayed`                            | already redeemed                                                                             |
| `handoff_expired`                     | its lifetime ran out                                                                         |
| `purpose_mismatch`                    | issued for another purpose than this endpoint redeems                                        |
| `application_mismatch`                | issued for another application                                                               |
| `connection_mismatch`                 | issued through another connection                                                            |
| `verifier_mismatch`                   | the verifier is not the one the flow was started with                                        |
| `connection_unavailable`              | the connection was disabled, deleted, left incomplete or its trust changed since completion  |
| `enforcement_unsatisfied`             | the tenant now requires sign-in through other connections                                    |
| `link_changed`                        | the link was removed, replaced, or (for a `sign_in`) appeared where there was none           |
| `link_suspended`                      | the link is suspended until a confirming `link`                                              |
| `principal_scope_unknown`             | the link's verified domain provenance needs a scope your contract could not judge, this once |
| `link_reserved`                       | a live reservation holds the subject, which a `link` waits out                               |
| `reservation_invalid`                 | the reservation is gone, expired, or a condition of it no longer holds                       |
| `identity_mismatch`                   | the caller is not the identity the `link` is bound to                                        |
| `freshness_required`                  | the caller of a `link` did not authenticate recently enough                                  |
| `link_ineligible`                     | the identity may not link through the connection                                             |
| `independent_authentication_required` | the identity holds a verified domain link, and the caller did not authenticate apart from it |
| `subject_already_linked`              | another identity holds the subject, which is never named                                     |
| `link_limit_reached`                  | the identity holds as many links in the connection as it may                                 |
| `session_ineligible`                  | the session is not active, or not bound to exactly this link                                 |
| `authentication_expired`              | an adapter's own `reauthenticate` result states no authentication time                       |

Never show a code to a person as it is: map it to your own wording. The result never shows its attributes in a dump or
`json_encode()`, and refuses to be serialised; keep `result` itself if you need it later.

## Transactions

Call `admit()` inside a transaction of your own on the package's storage connection, and write the session in it. The
redemption is then part of that transaction (a savepoint), its events wait for your commit, and the consumption, any
reservation's activation and your session commit or roll back together. A transaction on another connection is not
atomic with it (decision D5).

The locks the redemption takes are held until your transaction commits, so a change to enforcement waits for your
session to be written, and its revocation then removes it if the new rule does not allow it. A session written after
your transaction commits, or through another connection, is not covered: it can be created after the rule changed and
escape the change's revocation.

Two outcomes spend or keep the code, and they are not the same:

- **A refusal commits.** A check that refuses is an answer, not an error. Once the code is consumed, the refusal deletes
  that code's reservation, queues one failure event and, when your transaction commits, spends the code. Retrying with
  everything put right is `replayed`: the client must start again.
- **An exception rolls back.** A database error, or a contract that throws, propagates. It rolls back the consumption
  and any activation together, reports nothing, and leaves the code to be tried again. So does your own rollback, for
  whatever reason.

Retry only your whole transaction, from the start, and never a part of it.

> [!IMPORTANT]
> On PostgreSQL under `REPEATABLE READ`, a redemption that waited on another change to its connection can fail with a
> serialisation failure (SQLSTATE `40001`) instead of seeing the change. The package propagates it and never retries
> part of your transaction. Treat it as a server error, or retry your whole transaction from the start (the code is not
> spent, since the failure rolls everything back). Never catch it and carry on inside the same transaction.

## Redeeming codes of your own

An application that issues handoff codes of its own (binding `Contracts\HandoffIssuer` to its own store) redeems them
itself, through `Handoffs\HandoffRecheck`, inside the transaction that consumes its code, on the package's storage
connection. `laravel-iam` does not: the package issues, stores and redeems every code there too, and its adapter redeems
through `admit()` and `redeem()` (see [Integrating with `laravel-iam`](integrating-with-laravel-iam.md)). An
application redeeming its own codes describes what each was bound to with a `Handoffs\HandoffBinding`, built from what
its issuer stored: everything the issuer was given in its `HandoffGrant`.

Two of those your store must keep with the code (`Contracts\HandoffIssuer` requires both):

- **The trust version** (`$grant->trustVersion`): the connection's trust version as the completion read it under the
  connection's lock. Pass it back as the binding's `trustVersion`. The recheck compares it with the connection's under
  its lock, and refuses the code as `connection_unavailable` when they differ: the connection's trust changed between
  issuance and redemption (its certificates replaced, one distrusted, an anchor changed, its settings' trust changed,
  or the connection disabled and enabled again). The package voids its own codes on such a change too, but never yours:
  the version alone refuses them. A binding that names no trust version is refused the same way, so a store that does
  not keep it fails closed. Adding a provider key or certificate alone changes no version, and refuses nothing.
- **The session's latest end** (`$grant->sessionNotAfter`): set when the provider's deadline limits the session (see
  [Session provenance](session-provenance.md)), `null` when the deadline contract ignores it or there is none. Keep it
  exactly, or to the whole second as the package's own store does, never later. Cap the session you write at it, and
  pass it to `Provenance::capture()` with the admission, so the session and its provenance hold the same deadline.

It takes the recheck's lock first, before it locks its own code, so every redemption takes the package's lock order (the
identity's guard, the tenant's enforcement, the connections, a reservation's domain claim, the code, the links) and none
deadlocks with a change. Name the reservation the code holds, and for a `link` the identity it was started for: a `link`
judged under a lock that does not name it is a `LogicException`.

Your redeemer reads its code plainly from its store first (`$code`: the result it carries and everything its issuer
stored, or `handoff_unknown` when there is none), then runs the rest in one transaction, given the purpose its endpoint
redeems, the client's verifier and the caller. It imports `Illuminate\Support\Facades\DB` and, from
`SineMacula\Laravel\Sso`, `Database\StorageConnection`, `Events\Enums\FailureReason`, `Flows\Enums\Purpose`,
`Handoffs\HandoffBinding`, `Handoffs\HandoffRecheck` and `Sessions\Provenance`. Your store's `consume()` spends the code
exactly once (a conditional update of its row, through the storage connection) and answers `replayed` for a code spent
before; it then refuses a code that has expired, was issued for another purpose, or does not match the verifier, as the
package refuses its own. The redeemer answers `null` once the code is admitted, or the reason to refuse with:

<!-- snippet: tests/Integration/Examples/RedeemingAHandoff/OwnHandoffRedemption.php#own-code-redemption -->
```php
return DB::connection(StorageConnection::name())->transaction(function () use ($code, $purpose, $verifier, $caller): ?FailureReason {
    $result = $code->result;

    // The lock comes first, before your code is locked
    $recheck = app(HandoffRecheck::class);
    $lock    = $recheck->lock(
        $result->tenantId,
        $result->connectionId,
        $result->application,
        $code->reservationId,                                        // the reservation it holds, if any
        $result->purpose === Purpose::LINK ? $code->identity : null, // the identity of a `link` flow
    );

    // Your own atomic, single-use consumption, locked after, through
    // this same connection, with your own checks: a replay, the expiry,
    // the purpose your endpoint redeems and the verifier
    $refusal = $this->codes->consume($code, $purpose, $verifier);

    $binding = new HandoffBinding(
        linkedIdentity: $code->linkedIdentity, // the identity the result's link resolved to, if any
        linkId: $code->linkId,                 // the link observed at completion, active or suspended, if any
        identity: $code->identity,             // the identity of a `link` or `reauthenticate` flow
        sessionId: $code->sessionId,           // the session of a `reauthenticate` flow
        reservationId: $code->reservationId,   // the reservation it holds, if any
        handoffReference: $code->reference,    // the opaque reference your issuer answered
        trustVersion: $code->trustVersion,     // the connection's trust version it was issued under
    );

    $admission = $refusal === null ? $recheck->admit($result, $binding, $lock, $caller) : null;

    if ($admission === null || !$admission->isPassed()) {
        $recheck->discardReservation($binding, $result->connectionId);

        return $refusal ?? $admission?->outcome->reason(); // refuse; your code stays consumed
    }

    if ($result->purpose === Purpose::SIGN_IN && $admission->identity !== null) {
        $recheck->acknowledgeSignIn($result, $lock);

        // Write the session for the identity, bound to the link it
        // resolved through, never outliving the latest end your issuer
        // stored, with how it began, in this same transaction
        $this->signIns->start(
            $admission->identity,
            (string) $admission->linkId,
            $code->sessionNotAfter,
            Provenance::capture($result, $admission, $code->sessionNotAfter),
        );
    }

    // A `link` writes nothing further; a `reauthenticate` was renewed
    // by the admission
    return null;
});
```

- `lock()` takes the locks a redemption holds until your transaction ends: with the `enforcement` feature on and the
  default enforcement contract bound, the tenant's enforcement row (named by the inheritance contract, and inserted
  empty when the tenant has none) and then, in one statement in id order, the connection and the connections the rule
  names; otherwise the connection alone; then the domain claim of the reservation you name. Read your code plainly to
  learn the result before it, if you need to, but lock your code only after it.
- `admit()` is `recheck()` followed by the purpose's writes: activating a reservation, creating or confirming a link, or
  renewing a session. It answers an `Admission`: `isPassed()`, or the `outcome` that refused it, with the `identity`
  established, the `linkId` it resolved through, and the `evidence` accepted. `$outcome->reason()` gives the
  `FailureReason` to refuse with. Pass the caller your application has authenticated: a `link` needs it.
- `recheck()` alone judges, and writes nothing but a suspension it finds, which is latched whatever the redemption comes
  to. It takes the lock, and refuses one taken for another tenant, connection or application than the result's with a
  `LogicException`, so it cannot be reached without the locks. It answers `passed` or the first that refuses:
  `connection_unavailable` (also when the binding's trust version is not the connection's, or names none, and when the
  inheritance contract no longer names the tenant whose rule is locked),
  `enforcement_unsatisfied`, then the purpose's own. Under the default contract it judges enforcement from the locked
  rows.
- `discardReservation()` removes a refused code's reservation, by its identity and handoff reference and never merely by
  the subject, in your transaction; a binding with no reservation does nothing. Call it for every refusal after you
  consumed your code.
- `acknowledgeSignIn()` records the connection's completed sign-in on the locked row, only for a `sign_in` result; call
  it after the admission passed, for a result that established an identity.
- All of them throw a `LogicException` outside a transaction on the storage connection, and `acknowledgeSignIn()` for a
  result of another purpose. A lock is only good for the transaction it was taken in.
- A binding that does not say what the issuer was given fails closed. In particular, a `link`'s binding naming a linked
  identity but no link id cannot show the link is the same one, and is `link_changed`; one naming no identity is
  `identity_mismatch`.
- A serialisation failure on PostgreSQL propagates from `lock()`; retry your whole transaction, never a part of it. A
  refusal you commit spends your code, and a rollback does not, just as for the package's own.

If you bind your own `Contracts\Enforcement`, the recheck asks it, under the connection's lock alone. A current read in
your contract is not enough to keep a session from escaping a rule change: your contract must itself serialise the
admission against changes to its rule until the session's transaction commits (for example by locking the row your rule
lives in, in the same transaction), and your revocation must find sessions with current reads. If you bind your own
`Contracts\EnforcementInheritance`, it is asked inside the redeemer's transaction, before and after the locks: answer
from state that does not change under the transaction, or read it with a current read.

## Events

A redeemed code reports `HandoffRedeemed`, after `LinkCreated` or `LinkConfirmed` for a `link` that made or confirmed a
link, `LinkCreated` and `LinkActivated` for an activated reservation, and with `ReauthenticationCompleted` for a
`reauthenticate`. Every refusal, a full limit included, reports exactly one `FlowFailed` with the `redemption` flow and
the reason. Their context carries the connection, its tenant and protocol, the application, the
purpose, the request's public reference (`request_reference`, the only flow identifier events and logs carry), the
identity the flow concerns and, for a `reauthenticate`, the session. Never the code, the verifier, the subject or an
attribute, and never the caller or the identity holding the subject. A refusal before the code is found carries only the
purpose your endpoint asked for. All of them wait for your commit, and none is reported when your transaction rolls
back.

## Errors

A database error, a stored result the package did not write, and a contract that throws (your linker, your
enforcement) propagate as server errors: never as a refusal. They roll the redemption back, so the code is not spent.
