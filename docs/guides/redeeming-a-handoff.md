# Redeeming a Handoff

A completed flow ends with a redirect to your application's redirect URI carrying a single-use handoff code and the
request's public reference. Your client then exchanges the code, with the verifier it started the flow with, at a
redemption endpoint of your API, which answers with whatever your application signs people in with. The package's
redemption helper does the checking; your application owns the route and the response.

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
POST /auth/sso/handoffs
Content-Type: application/json

{"code": "<the code from the redirect>", "verifier": "<the verifier the client kept>"}
```

```php
namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;

final class SsoHandoffController
{
    public function __construct(
        private readonly HandoffRedemption $redemptions,
    ) {}

    public function signIn(Request $request): JsonResponse
    {
        $result = $this->redemptions->redeem(
            Purpose::SIGN_IN,
            'web',                                   // your application's name, as configured
            (string) $request->input('connection'),  // the connection the client started through
            (string) $request->input('code'),
            (string) $request->input('verifier'),
        );

        if ($result->isRateLimited()) {
            return response()->json(['error' => 'rate_limited'], 429, [
                'Retry-After'   => (string) $result->retryAfter,
                'Cache-Control' => 'no-store',
            ]);
        }

        if (!$result->isRedeemed()) {
            return response()->json(['error' => $result->reason?->value], 400, ['Cache-Control' => 'no-store']);
        }

        // Sign in the identity $result->linkedIdentity names, with $result->result.
        $token = $this->issueYourOwnToken($result);

        return response()->json(['token' => $token], 200, ['Cache-Control' => 'no-store']);
    }
}
```

Send every answer with `Cache-Control: no-store` (SSO-9.8): the request carried a verifier and a code, and the
response carries your application's credentials. Never echo the code or the verifier back.

The purpose is your endpoint's, never the request's: a sign-in endpoint redeems `Purpose::SIGN_IN` codes only, and a
`link` or `reauthenticate` code presented there is refused (SSO-9.9). Give each purpose its own endpoint.

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
8. The connection must still be enabled and complete, still satisfy its tenant's enforcement, and the result's link
   must still resolve to the identity it resolved to at completion.

A redeemed `sign_in` code that resolved to an identity records that the connection has completed a sign-in, which
enforcement needs before it can be turned on for the tenant (SSO-4.3). A `link` or `reauthenticate` code, an unlinked
handoff and a code that was never redeemed never do.

## The results

| Result         | When                                 | Your response              |
|----------------|--------------------------------------|----------------------------|
| redeemed       | every check passed                   | sign in, link or renew     |
| refused        | a check failed, for its `reason`     | a `400` with the code      |
| rate limited   | the limit for the IP address is full | a `429` with `Retry-After` |

A redeemed result carries:

- `result`: the `VerifiedResult` (issuer, subject, connection, tenant, protocol, application, purpose, reference, the
  mapped attributes and the provider's authentication context);
- `linkedIdentity`: the identity the result's link resolved to at completion, and still resolves to; `null` for an
  unlinked handoff, whose identity your application resolves itself (never from the email or another attribute);
- `identity`: the identity a `link` or `reauthenticate` flow was started for, and `sessionId` the session a
  `reauthenticate` flow was started on;
- `enforcementVersion`: the enforcement version the completion checked, and `sessionNotAfter`, the latest end of your
  session the provider's deadline sets. Keep both on the session you create (SSO-9.10).

A refused result carries one of these codes:

| Code                      | Why                                                                                    |
|---------------------------|----------------------------------------------------------------------------------------|
| `handoff_unknown`         | not a code, never issued, or voided by a change to its connection                      |
| `replayed`                | already redeemed                                                                       |
| `handoff_expired`         | its lifetime ran out                                                                   |
| `purpose_mismatch`        | issued for another purpose than this endpoint redeems                                  |
| `application_mismatch`    | issued for another application                                                         |
| `connection_mismatch`     | issued through another connection                                                      |
| `verifier_mismatch`       | the verifier is not the one the flow was started with                                  |
| `connection_unavailable`  | the connection was disabled, deleted or left incomplete since completion               |
| `enforcement_unsatisfied` | the tenant now requires sign-in through other connections                              |
| `link_changed`            | the link was removed, now names another identity, or appeared where there was none     |

Never show a code to a person as it is: map it to your own wording. The result never shows its attributes in a dump or
`json_encode()`, and refuses to be serialised; keep `result` itself if you need it later.

## Transactions

Call the helper inside a transaction of your own on the package's storage connection when your sign-in must commit
with the redemption: the redemption is then part of it (a savepoint), its events wait for your commit, and a rollback
undoes it, the consumed code included, so the client can try again. A transaction on another connection is not atomic
with it (decision D5).

## Redeeming codes of your own

An adapter that issues handoff codes of its own (binding `Contracts\HandoffIssuer` to its store, as `laravel-iam`
binds `laravel-authentication`'s codes) redeems them itself, and asks the package's recheck inside the transaction
that consumes its code, on the package's storage connection:

```php
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;

DB::connection(StorageConnection::name())->transaction(function () use ($code, $result, $linkedIdentity) {
    $code->consume(); // your own atomic, single-use consumption, through this same connection

    $outcome = app(HandoffRecheck::class)->recheck($result, $linkedIdentity);

    if ($outcome !== RecheckOutcome::PASSED) {
        return $outcome->reason(); // refuse; your code stays consumed
    }

    if ($result->purpose === Purpose::SIGN_IN && $linkedIdentity !== null) {
        app(HandoffRecheck::class)->acknowledgeSignIn($result);
    }

    // sign in, link or re-authenticate
});
```

- `recheck()` answers `passed`, or the first of `connection_unavailable`, `enforcement_unsatisfied` and
  `link_changed`; `reason()` gives the `FailureReason` to refuse with. It locks the connection's row until your
  transaction ends.
- `acknowledgeSignIn()` records the connection's completed sign-in, only for a `sign_in` result; call it after the
  recheck passed, for a result linked to an identity.
- Both throw a `LogicException` outside a transaction on the storage connection, and `acknowledgeSignIn()` for a
  result of another purpose.

## Events

A redeemed code reports `HandoffRedeemed`; every refusal, a full limit included, exactly one `FlowFailed` with the
`redemption` flow and the reason. Their context carries the connection, its tenant and protocol, the application, the
purpose, the request's public reference (`request_reference`, the only flow identifier events and logs carry), the
identity and, for a `reauthenticate`, the session. Never the code, the verifier, the subject or an attribute. A
refusal before the code is found carries only the purpose your endpoint asked for.

## Errors

A database error, a stored result the package did not write, and a contract that throws (your linker, your
enforcement) propagate as server errors: never as a refusal. They roll the redemption back, so the code is not spent.
