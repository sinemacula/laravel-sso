# Discovery

Discovery lets a person type their email address instead of choosing their organisation's identity provider. The
package takes the address's domain, finds the enabled connection that domain is verified for, and starts the flow
through it. A domain that routes nowhere leads to your application's own sign-in page instead, in an answer your client
cannot tell apart from a match by its shape or status, and that is padded to a minimum duration so its timing does not
give it away either, as long as the match finishes within that duration. The helper is `Discovery\DiscoveryService`:

<!-- snippet: tests/Integration/Examples/Discovery/DiscoveryExampleTest.php#discovery-service -->
```php
$discovery = app(DiscoveryService::class);
```

Resolve the service from the container for each request: it keeps nothing of one request for the next, and never reads
the request being served. `start()` takes the client the flow is started for as an `Http\ClientContext`, which your
route builds with `ClientContext::fromRequest($request)`: the start is counted against its IP address, and every event
the start reports carries its IP address and user agent.

## Turning it on

Discovery is opt-in twice: the `discovery` feature, and each application that offers it.

<!-- snippet: tests/Integration/Examples/Discovery/config/sso.php#discovery-configuration -->
```php
// config/sso.php
'features' => [
    'oidc'      => true,
    'discovery' => true,
],

'applications' => [
    'web' => [
        'redirect_uri'     => 'https://app.example.com/auth/sso/complete',
        'external_sign_in' => true,
        'discovery'        => ['enabled' => true, 'fallback_url' => 'https://app.example.com/sign-in'],
    ],
],
```

While both are on, `fallback_url` is required: the boot check (`[applications]`) refuses an application that offers
discovery without one. It is an exact redirect URI, like `redirect_uri`, and a native application may give its own
scheme (`com.example.app:/sign-in`).

Only a verified domain routes discovery (see [Domains](domains.md)). Claims are exact: verifying `example.com` routes
`jane@example.com`, not `jane@mail.example.com`.

## An example route

The package registers no routes. One layout you might use, beside the named start of
[Starting a Flow](starting-a-flow.md):

```text
POST   /auth/sso/discovery     start: {application, email, code_challenge?}
                               -> {reference, navigation, verifier?}
```

In your routes file:

<!-- snippet: tests/Integration/Examples/Discovery/routes.php#discovery-route -->
```php
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use SineMacula\Laravel\Sso\Discovery\DiscoveryService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Http\ClientContext;

Route::post('/auth/sso/discovery', static function (Request $request, DiscoveryService $discovery): JsonResponse {
    $result = $discovery->start(
        application: $request->string('application')->toString(),
        purpose: Purpose::SIGN_IN,
        email: $request->string('email')->toString(),
        client: ClientContext::fromRequest($request),
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
`Retry-After`. The purposes, the identity and the session work exactly as they do for a named start, and come from your
own authentication, never from the request body.

## The answer

A match and a miss answer alike:

```json
{
    "reference": "Rq8tVv3w0kLmNoPqRsTuVwXyZ0123456",
    "navigation": {"type": "redirect", "url": "https://idp.example.com/authorize?..."},
    "verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
}
```

- Both are `started`, with the same keys: `reference`, `navigation`, and `verifier` exactly when your client sent no
  `code_challenge`.
- Both navigations are a `redirect`. A match's leads to the identity provider; a miss's leads to the application's
  `fallback_url`.
- A miss's reference names no request, and its verifier redeems nothing. Your client treats both answers the same way:
  keep the verifier with the reference, and navigate.

A miss is any of: a domain nobody has claimed, a claim still pending, a domain that lapsed or whose grace period after
its record went has ended, a disabled or incomplete connection, and an address with no domain that could be registered
(no `@`, `localhost`, an IP address). None is told apart from the others.

> [!IMPORTANT]
> Discovery never reveals whether a person has an account: it reads only the domain, never a user. But where the answer
> leads still shows whether a domain routes to an identity provider, as any discovery does. Anyone can learn that
> `example.com` signs in through single sign-on by trying an address at it. Do not offer discovery where that fact is
> itself sensitive.

### The minimum duration

Every answer, a refusal included, takes at least `sso.discovery.minimum_duration_milliseconds` (50 to 2000, 250 by
default), measured from when the start began. This is a timing mitigation: a match (which reads the connection, asks
the driver to start and stores the request) and a miss (which reads one row) that both finish within the floor answer
after the same time. It cannot be turned off, and a value outside its range fails the boot check (`[flows]`).

It is not a guarantee that the two are indistinguishable. An answer whose work outlasts the floor, because a driver
reads metadata or calls the identity provider, or because the database is slow, is not held back further, so its time
can still differ from a miss's. Set the floor above the slowest match you expect, and watch for matches that exceed it.
A mistake in your code (a misbound purpose) and a server error are thrown at once, not held.

> [!NOTE]
> Every discovery start sleeps out the rest of the floor, holding its worker for that long. Plan capacity for it: the
> workers that serve discovery must cover the discovery rate multiplied by the floor, on top of the real work, and a
> higher floor needs more of them.

## Refusals

A refused answer's body is `{"error": "<reason>"}`, and a rate limited one adds `"retry_after"` in seconds:

| Error                     | Why                                                                                   |
|---------------------------|---------------------------------------------------------------------------------------|
| `rate_limited`            | The client's IP address or the email's domain used up its starts                      |
| `application_not_allowed` | The application is not registered, or does not allow external sign-in                 |
| `feature_disabled`        | The application does not offer discovery, or the `discovery` feature is off           |
| `challenge_invalid`       | `code_challenge` is not an S256 challenge: 43 base64url characters, with no padding   |
| `freshness_required`      | A `link` that matched, from a caller who did not authenticate recently enough         |
| `session_ineligible`      | A `reauthenticate` that matched, for an identity not signed in through the connection |

A protocol driver that cannot start answers its own reason (for example `metadata_expired`). A matched connection
disabled or changed while its driver started leads to the fallback, as a miss does.

## Rate limits

Starts are counted per IP address (`sso.rate_limits.authorization_request.per_ip`, 30 a minute by default) and per email
domain (`sso.rate_limits.authorization_request.per_email_domain`, 300 a minute by default), successful or not. The
domain is counted in its normalised form, so `Jane@EXAMPLE.com.` and `jane@example.com` share one counter; the address
itself is never counted or stored. An address whose domain does not normalise is counted against the IP address alone. A
start made for no client (`new ClientContext(null, null)`, from a console command) counts against no address. See [Rate
Limits](rate-limits.md).

## Events

- A match reports `AuthorizationRequestStarted`, as a named start does.
- A miss reports exactly one `FlowFailed` with `flow` `authorization_request` and `reason` `discovery_no_match`. Its
  context names the application and the purpose (and the identity and session of a `link` or `reauthenticate`), never
  the email, its domain or a connection.
- Every refusal reports exactly one `FlowFailed` with its reason.

No event or log carries the email address or its domain. See [Events](events.md).
