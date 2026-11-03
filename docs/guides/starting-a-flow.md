# Starting a Flow

A flow starts when your client (a browser application, a native application) asks your API to sign in through a
connection. The API records an authorisation request and answers with its public reference and a navigation that sends
the browser to the identity provider. The package gives you the answer as a value; your application owns the route and
the response.

<!-- snippet: tests/Integration/Examples/StartingAFlow/service.php#resolve-service -->

```php
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;

$requests = app(AuthorizationRequestService::class);
```

Resolve the service from the container for each request: it reads the request being served (for its IP address) and
keeps nothing of one request for the next.

## An example route

The package registers no routes. One layout you might use:

```text
POST   /auth/sso/authorization-requests     start: {application, connection, code_challenge?}
                                            -> {reference, navigation, verifier?}
```

<!-- snippet: tests/Integration/Examples/StartingAFlow/routes.php#authorization-requests-route -->

```php
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;

Route::post('/auth/sso/authorization-requests', static function (Request $request, AuthorizationRequestService $requests): JsonResponse {
    $result = $requests->start(
        application: $request->string('application')->toString(),
        purpose: Purpose::SIGN_IN,
        connectionId: $request->string('connection')->toString(),
        codeChallenge: $request->has('code_challenge') ? $request->string('code_challenge')->toString() : null,
    );

    $status = match (true) {
        $result->isStarted()     => 200,
        $result->isRateLimited() => 429,
        default                  => 400,
    };

    return response()->json($result->body(), $status, $result->headers());
});
```

Always send `headers()` with the body: every answer carries `Cache-Control: no-store`, and a rate limited one
`Retry-After`. A started answer may carry a verifier, which must never be cached by the browser, a proxy or a CDN.

The application name comes from your client and is checked exactly against `sso.applications`. The purpose and, for
`link` and `reauthenticate`, the identity and the session must come from your own authentication, never from the
request body (see [Purposes](#purposes)).

## The answer

A started answer's body is:

```json
{
    "reference": "Rq8tVv3w0kLmNoPqRsTuVwXyZ0123456",
    "navigation": {"type": "redirect", "url": "https://idp.example.com/authorize?..."},
    "verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
}
```

- `reference` is the request's public reference: 32 base64url characters, not a secret, and the only identifier of the
  flow that appears in events, logs and the completion's redirect.
- `navigation` is where the browser goes. A `redirect` has a `url`: navigate the top-level window to it. A `post` has a
  `url` and `fields` (a SAML HTTP-POST `AuthnRequest`): build a form with a hidden input for each field, its `action`
  the `url`, and submit it.
- `verifier` is present only when your client sent no `code_challenge`: the package generated it, and this is the only
  time it is ever returned.

A refused answer's body is `{"error": "<reason>"}`, and a rate limited one adds `"retry_after"` in seconds:

| Error                     | Why                                                                                                    |
|---------------------------|--------------------------------------------------------------------------------------------------------|
| `rate_limited`            | The client's IP address used up its starts (`sso.rate_limits.authorization_request.per_ip`)            |
| `application_not_allowed` | The application is not registered, or does not allow sign-in through an external provider              |
| `challenge_invalid`       | `code_challenge` is not an S256 challenge: 43 base64url characters, with no padding                    |
| `connection_unavailable`  | The connection is unknown, disabled, of a protocol switched off, incomplete, or changed while starting |
| `freshness_required`      | A `link` from a caller who did not authenticate recently enough                                        |
| `session_ineligible`      | A `reauthenticate` for an identity not signed in through the connection on the session                 |

A protocol driver that cannot start answers its own reason (for example `metadata_expired`). Each refusal stores
nothing and reports one `FlowFailed` event with the reason.

> [!NOTE]
> An application that offers discovery (`sso.applications.<name>.discovery.enabled`, with the `discovery` feature on)
> is never told that a named connection is unknown or disabled: the answer is `started`, in the same shape, with a
> fresh reference, a verifier when no challenge was sent, and a navigation to the application's `fallback_url`. The
> failure is still reported as `connection_unavailable`. An application that does not offer discovery has no fallback
> to answer with, so it is told `connection_unavailable` (a recommended default of 2026-11-03, RD-33 in the
> [requirement closure matrix](../design/requirements.md#recorded-decisions): there is no fallback answer without
> discovery). [Discovery](discovery.md) starts a flow from an email address instead of a named connection.

## The client's duties

The package binds the flow to the client that started it with a verifier, as PKCE does (RFC 7636): only the client
holding the verifier can redeem the handoff code the flow ends with. This works only if the client does its part
(SSO-5.12):

- **Generate a fresh verifier per request**, or let the package generate it. A verifier is 43 to 128 unreserved
  characters (`A-Z`, `a-z`, `0-9`, `-`, `.`, `_`, `~`) with at least 256 bits of entropy, from a cryptographic random
  source (`crypto.getRandomValues()`, `SecRandomCopyBytes`), never reused. Send only its challenge,
  `BASE64URL(SHA-256(verifier))` without padding, as `code_challenge`.
- **Keep the verifier with the request's public reference**, in memory or storage scoped to your application
  (`sessionStorage`, the platform's keychain), never in a URL, a cookie shared with other sites or a log.
- **Redeem only a handoff whose reference matches a request it started**. A completion's redirect carries the reference;
  a code arriving with a reference your client did not start is an attack, and is discarded.
- **Send the code and the verifier in a POST body**, never in a URL.
- **Remove the code from the address bar and the history at once** (`history.replaceState()`), before anything else
  runs on the page.

The verifier is independent of the PKCE verifier the package uses with the identity provider, which never leaves your
API, and of the `state` or `RelayState` sent to the provider, which are random values of their own.

## Purposes

| Purpose          | Identity     | Session | Before it starts                                                                  |
|------------------|--------------|---------|-----------------------------------------------------------------------------------|
| `sign_in`        | none         | none    | nothing more                                                                      |
| `link`           | the caller's | none    | the freshness contract is asked `sso.link.create` (see [Freshness](freshness.md)) |
| `reauthenticate` | the caller's | its id  | `Contracts\ReauthenticationSessions` must answer `signed_in`                      |

<!-- snippet: tests/Integration/Examples/StartingAFlow/caller.php#start-for-the-caller -->

```php
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

$identity = new IdentityReference($user->getMorphClass(), (string) $user->getKey());

$linking          = $requests->start('web', Purpose::LINK, $connectionId, $challenge, $identity);
$reauthenticating = $requests->start('web', Purpose::REAUTHENTICATE, $connectionId, $challenge, $identity, $sessionId);
```

Any other combination, or a session id that is empty or longer than 255 bytes, is an `InvalidArgumentException`: a
mistake in your code, not a refusal.

> [!IMPORTANT]
> The default freshness contract refuses every operation, so every `link` is refused with `freshness_required` until
> you bind your own. The package keeps no sessions, so its default `ReauthenticationSessions` answers `not_signed_in`
> and every `reauthenticate` is refused with `session_ineligible` until you bind one that reads your sessions. Under
> `laravel-iam` both are bound for you.

## Lifetime and limits

- A request lives `sso.authorization_requests.ttl_seconds` (60 to 900 seconds, 600 by default) and is consumed once,
  by the first response that names it, whether that response then passes or fails. A second response for it is
  refused.
- Starts are counted per IP address under `sso.rate_limits.authorization_request.per_ip` (30 a minute by default),
  successful or not. With no request being served (a console command) no address is counted.

## Events

A start reports `AuthorizationRequestStarted` once the request is stored and its transaction commits, with the
connection, its tenant and protocol, the application, the purpose, the `request_reference`, and the identity and
session given. A refusal reports exactly one `FlowFailed` with the flow `authorization_request` and its reason. No event
carries the protocol state, the nonce, a verifier or the challenge (see [Events](events.md)).

## Transactions

Call `start()`, and discovery's `start()`, outside any transaction of your own on the package's storage connection.
Called inside one, a start throws a `LogicException` before it counts, asks or stores anything: it calls the protocol
driver, which may reach the identity provider, and your transaction would keep the connection's lock all the while.
