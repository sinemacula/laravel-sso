# Completing a Flow

Once the browser has signed in at the identity provider, the provider sends it back to your API: a SAML response is
posted to the connection's assertion consumer service, an OIDC authorisation response arrives at the connection's
callback. The completion helper validates the response, consumes the authorisation request, builds the verified
result, resolves its link, checks enforcement and issues a single-use handoff code for your client. It answers a
`CompletionResult` value; your application owns the routes and turns the result into a response.

```php
use SineMacula\Laravel\Sso\Completion\CompletionService;

$completions = app(CompletionService::class);
```

Resolve the service from the container for each request: it reads the request being served (for its IP address) and
keeps nothing of one request for the next.

## The routes

The package registers no routes. With the example layout (SSO-12.5):

```text
POST   /auth/sso/connections/{connection}/assertions    SAML assertion consumer service
GET    /auth/sso/connections/{connection}/callback      OIDC redirect URI
```

These are the paths `sso.endpoints.paths` builds the URLs from, so the URL an identity provider is given for a
connection, and the route that receives its response, are the same. Keep them in step: a completion is accepted only
for the connection the route names, and a response that names a request of another connection fails with
`connection_mismatch`.

The routes take no session, no CSRF token and no authentication: the response is checked by the completion itself. Put
them outside the `web` middleware group, or exclude them from CSRF verification, since a SAML response is a cross-site
POST.

```php
// routes/api.php
use App\Http\Controllers\SsoCompletionController;

Route::post('/auth/sso/connections/{connection}/assertions', [SsoCompletionController::class, 'assertion']);
Route::get('/auth/sso/connections/{connection}/callback', [SsoCompletionController::class, 'callback']);
```

```php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Responses\CompletionResponse;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;

final class SsoCompletionController
{
    public function __construct(
        private readonly CompletionService $completions,
        private readonly CompletionResponses $responses,
    ) {}

    // POST: the SAML response, posted by the browser
    public function assertion(Request $request, string $connection): CompletionResponse
    {
        $result = $this->completions->assertionConsumerService($connection, CompletionRequest::fromRequest($request));

        return $this->responses->from($result, $request->getMethod());
    }

    // GET: the OIDC authorisation response
    public function callback(Request $request, string $connection): CompletionResponse
    {
        $result = $this->completions->callback($connection, CompletionRequest::fromRequest($request));

        return $this->responses->from($result, $request->getMethod());
    }
}
```

`CompletionRequest::fromRequest()` keeps the method, the raw query string and the posted fields, and nothing else: it
never reaches a log, an event or a queue. [Completion responses](completion-responses.md) explains the statuses, the
redirect and the headers each result answers with.

## What a completion does

Each call runs in a fixed order, and stops at the first step that refuses:

1. The completion is counted against the client's IP address and the connection (`sso.rate_limits.completion`); a full
   limit answers `rate_limited`.
2. The method must be the endpoint's: `POST` at the assertion consumer service, `GET` at the callback.
3. The connection is read by its id, and its protocol must complete at this endpoint: `saml2` at the assertion consumer
   service, `oidc` at the callback. A protocol you registered with `ProtocolManager::extend()` completes at either.
4. The connection's driver reads which authorisation request the response answers.
5. That request is consumed, before anything in the response is validated, so it is consumed once whether the response
   then passes or fails. A disabled connection still consumes the request its response names, so its failure goes back
   to your application.
6. The driver validates the response against the request, and the verified result is built: the issuer, subject,
   connection, tenant, protocol, application, purpose, the mapped attributes, whether the email's domain is verified
   for this connection, and the provider's authentication context.
7. Under the connection's and the request's locks, in one transaction: the connection must still be usable and the
   request not voided by a change to its connection; the result's link is resolved through your `Linker`; the
   connection must satisfy its tenant's enforcement; an unlinked `sign_in` ends unless the application allows unlinked
   handoffs; the application policy is asked again; and the handoff code is issued.
8. The request is marked completed, and the events are reported once the transaction commits.

## The results

| Result         | When                                                                 | Your response                         |
|----------------|----------------------------------------------------------------------|---------------------------------------|
| `completed`    | a code was issued                                                    | redirect with `code` and `reference`  |
| `failed`       | refused once the request was found, for a registered application     | redirect with `error` and `reference` |
| `rejected`     | refused with no trusted target: no request matched, or no connection | a `400`, no redirect                  |
| `rate_limited` | a completion limit is full                                           | a `429` with `Retry-After`            |

A `failed` result carries one of these codes (the protocol drivers add the validation codes of SAML and OIDC):

| Code                      | Why                                                                                        |
|---------------------------|--------------------------------------------------------------------------------------------|
| `connection_unavailable`  | the connection was disabled, or its trust changed, since the flow started                  |
| `connection_mismatch`     | the response arrived at another connection's endpoint than its request was started through |
| `request_expired`         | the request's lifetime (`sso.authorization_requests.ttl_seconds`) ran out                  |
| `enforcement_unsatisfied` | the tenant requires sign-in through other connections                                      |
| `unlinked`                | a `sign_in` resolved to no identity, and the application does not allow unlinked handoffs  |
| `application_not_allowed` | the application no longer allows sign-in through an external provider                      |

A `rejected` result carries `request_unknown` (a wrong method, a response that names no request, a replay),
`connection_unavailable` (an unknown connection, or a protocol that does not complete at this endpoint) or
`application_not_allowed` (the request's application is no longer configured, so there is no redirect URI to trust).
Never show a code to a person as it is: map it to your own wording.

Your client then redeems the code with its verifier: [Redeeming a handoff](redeeming-a-handoff.md) shows how, and what
redemption checks again.

## Unlinked sign-ins

A `sign_in` whose verified issuer and subject are linked to no identity ends with `unlinked` by default. An application
that resolves identities itself when it redeems the code can allow unlinked handoffs:

```php
'applications' => [
    'web' => [
        'redirect_uri'      => 'https://app.example.com/sso',
        'external_sign_in'  => true,
        'unlinked_handoffs' => true,
    ],
],
```

Its codes then carry no linked identity, and the redemption must decide who signed in. Never resolve an identity from
the email or any other mapped attribute: only a link (issuer, subject, connection) identifies a person.

`link` and `reauthenticate` flows are never refused as unlinked here.

## The contracts it asks

Bind your own in a service provider's `register()`; each default fails closed.

- `Contracts\Linker`: the identity a verified result is linked to. The default links nothing; bind the package's
  `Links\LinkStore`, or your own.
- `Contracts\Enforcement`: whether the connection satisfies its tenant's enforcement on the application; the version
  checked travels with the code, and redemption checks enforcement again.
- `Contracts\ApplicationPolicy`: asked again just before the code is issued.
- `Contracts\ProviderSessionDeadline`: whether the provider's session deadline (SAML `SessionNotOnOrAfter`) limits your
  application's session. By default it does, and the code carries the deadline as the session's latest end; bind your
  own to answer `ignored` when your sessions are independent of the provider's.
- `Contracts\HandoffIssuer`: issues the code, inside the completion's transaction on the package's storage connection.
  An issuer that writes through another connection is not atomic with the completion. An issuer that cannot issue
  throws, and the completion is rolled back as a server error.

## Events

A completed flow reports `ResultVerified` then `HandoffIssued`. A refusal once the response was verified reports
`ResultVerified` then one `FlowFailed`; any earlier refusal, a full limit included, one `FlowFailed`, with the flow
(`assertion` or `callback`) and the reason. Their context carries the connection, its tenant and protocol, the
application, the purpose and the request's public reference (`request_reference`, the only flow identifier events and
logs carry); the linked identity for a `sign_in`, the identity a `link` or `reauthenticate` was started for, and the
session of a `reauthenticate`. Never a subject, an attribute or a code.

Events are dispatched after the completion's transaction commits.

## Transactions

Call the helper outside any transaction of your own on the package's storage connection: do not wrap the assertion
consumer service or callback route in `DB::transaction()`. Called inside one, a completion throws a `LogicException`
before it writes anything. Were it part of your transaction, your rollback would undo the request's consumption and let
the same response be replayed, and your transaction would hold the connection's lock while the driver validates the
response.

## Errors

A database error, a misconfigured contract and an issuer that throws propagate as server errors: they are never
answered as a failure redirect or a `400`, and they reach your exception handler as any other error does. A completion
rolled back by one leaves its request consumed, so the browser has to start again.
