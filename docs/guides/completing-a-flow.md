# Completing a Flow

Once the browser has signed in at the identity provider, the provider sends it back to your API: a SAML response is
posted to the connection's assertion consumer service, an OIDC authorisation response arrives at the connection's
callback. The completion helper validates the response, consumes the authorisation request, builds the verified
result, resolves its link, checks enforcement and issues a single-use handoff code for your client. A result with no
link may be [reserved by a verified domain](linking-by-domain.md) or offered for [provisioning](provisioning.md), and a
[`reauthenticate`](reauthenticating.md) has rules of its own. It answers a `CompletionResult` value; your application
owns the routes and turns the result into a response.

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
7. In one transaction, under the tenant's enforcement lock (with the `enforcement` feature on and the default
   enforcement contract), the connection's lock (taken with the rule's connections, in id order) and the request's:
   the connection must still be usable and the request not voided by a change to its connection; the result's link is
   resolved through your `Linker`; the connection must satisfy its tenant's enforcement as the locked rule has it; the
   flow's purpose must allow what the link came to; an eligible unlinked `sign_in` reserves a link through a
   [verified domain](domains.md). A change to enforcement made at the same moment waits for this transaction, or is
   seen by it.
8. A result linked or holding a reservation, and every `link` and `reauthenticate`, finishes in that transaction: the
   application policy is asked again and the handoff code is issued.
9. A `sign_in` still unlinked crosses the [provisioning boundary](provisioning.md): that transaction commits, no code
   issued; the unlinked-result event is dispatched synchronously, with no package transaction open; and a final
   transaction takes the same locks again and checks everything once more. It resolves the link anew, ends with
   `unlinked` unless the application allows unlinked handoffs, asks the application policy again and issues the code. It
   never records the response against replay again, selects a domain or offers the result again.
10. The request is marked completed, and the events are reported once the transaction commits.

## The results

| Result         | When                                                                 | Your response                         |
|----------------|----------------------------------------------------------------------|---------------------------------------|
| `completed`    | a code was issued                                                    | redirect with `code` and `reference`  |
| `failed`       | refused once the request was found, for a registered application     | redirect with `error` and `reference` |
| `rejected`     | refused with no trusted target: no request matched, or no connection | a `400`, no redirect                  |
| `rate_limited` | a completion limit is full                                           | a `429` with `Retry-After`            |

A `failed` result carries one of these codes (the protocol drivers add the validation codes of SAML, in
[Signing In with SAML](saml-sign-in.md), and of OIDC, in [The OIDC Callback](oidc-callback.md) and
[OIDC ID Tokens](oidc-id-tokens.md)):

| Code                      | Why                                                                                                          |
|---------------------------|--------------------------------------------------------------------------------------------------------------|
| `connection_unavailable`  | the connection was disabled, or its trust changed, since the flow started                                    |
| `connection_mismatch`     | the response arrived at another connection's endpoint than its request was started through                   |
| `request_expired`         | the request's lifetime (`sso.authorization_requests.ttl_seconds`) ran out                                    |
| `enforcement_unsatisfied` | the tenant requires sign-in through other connections                                                        |
| `unlinked`                | a `sign_in` still resolved to no identity once offered, and the application does not allow unlinked handoffs |
| `application_not_allowed` | the application no longer allows sign-in through an external provider                                        |

A `rejected` result carries `request_unknown` (a wrong method, a response that names no request, a replay),
`connection_unavailable` (an unknown connection, or a protocol that does not complete at this endpoint) or
`application_not_allowed` (the request's application is no longer configured, so there is no redirect URI to trust).
Never show a code to a person as it is: map it to your own wording.

Your client then redeems the code with its verifier: [Redeeming a handoff](redeeming-a-handoff.md) shows how, and what
redemption checks again.

## Unlinked sign-ins

A `sign_in` whose verified issuer and subject are linked to no identity, and which holds no reservation, is first
offered to the listeners of `Events\ResultUnlinked`, synchronously and before any handoff, with a single-use grant. A
listener can create a new identity, its membership and the link just in time: [Provisioning](provisioning.md) shows how.

- A queued listener is too late, and fails loudly: the event refuses to be serialised, so queuing it is a server error.
- Resolving an existing identity from the email or any mapped attribute is forbidden. Attaching to an existing identity
  goes through a `link` flow or a [verified domain](domains.md), and only a link (issuer, subject, connection)
  identifies a person.
- A listener wraps the identity, its membership and the link in one transaction on the package's storage connection, and
  rolls it back when the helper refuses. That the identity is new is its obligation: the package creates no identity and
  cannot tell.
- A provisioned identity can survive a later failure of the completion, since provisioning runs outside the package's
  locks.

The link is then resolved again. A result still unlinked ends with `unlinked` by default. An application that resolves
identities itself when it redeems the code can allow unlinked handoffs:

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
the email or any other mapped attribute there either. An unlinked handoff is only for a link that is genuinely absent:
a suspended link ends with `link_suspended`, and another flow's live reservation with `link_reserved`, whatever this
setting says. Under `laravel-iam` the sign-in adapter always requires a linked identity.

`link` and `reauthenticate` flows are never refused as unlinked here, and never offered for provisioning.

## The contracts it asks

Bind your own in a service provider's `register()`; each default fails closed.

- `Contracts\Linker`: the identity a verified result is linked to. The default links nothing; bind the package's
  `Links\LinkStore`, or your own.
- `Contracts\Enforcement`: whether the connection satisfies its tenant's enforcement on the application; the version
  checked travels with the code, and redemption checks enforcement again. Under the default, the completion locks the
  rule and judges it from the locked rows. A contract of your own is asked as it is bound, and must itself keep a
  change to its rule from slipping in between its answer and the session it admits (a current read alone is not
  enough); a `Contracts\EnforcementInheritance` of your own is asked inside the completion's transaction, so answer it
  from state that does not change under that transaction, or with a current read.
- On PostgreSQL under `REPEATABLE READ`, a completion that waited on an enforcement change can fail with a
  serialisation failure (SQLSTATE `40001`); it is thrown as a server error, and the person starts the flow again.
- `Contracts\ApplicationPolicy`: asked again just before the code is issued.
- `Contracts\ProviderSessionDeadline`: whether the provider's session deadline (SAML `SessionNotOnOrAfter`) limits your
  application's session. By default it does, and the code carries the deadline as the session's latest end; bind your
  own to answer `ignored` when your sessions are independent of the provider's.
- `Contracts\HandoffIssuer`: issues the code, inside the completion's transaction on the package's storage connection.
  An issuer that writes through another connection is not atomic with the completion. An issuer that cannot issue
  throws, and the completion is rolled back as a server error.

## Events

A completed flow reports `ResultVerified` then `HandoffIssued`. A refusal once the response was verified reports
`ResultVerified` then one `FlowFailed`. A `sign_in` still unlinked reports `ResultVerified`, then `ResultUnlinked`, then
what its listener made and how it ended ([Provisioning](provisioning.md)). Any earlier refusal, a full limit included,
reports one `FlowFailed`, with the flow
(`assertion` or `callback`) and the reason. Their context carries the connection, its tenant and protocol, the
application, the purpose and the request's public reference (`request_reference`, the only flow identifier events and
logs carry); the linked identity for a `sign_in`, the identity a `link` or `reauthenticate` was started for, and the
session of a `reauthenticate`. Never a subject, an attribute or a code.

Events are dispatched after the transaction that caused them commits, but for `ResultUnlinked`, which is synchronous by
design and is the one event that carries the result.

## Transactions

Call the helper outside any transaction of your own on the package's storage connection: do not wrap the assertion
consumer service or callback route in `DB::transaction()`. Called inside one, a completion throws a `LogicException`
before it writes anything. Were it part of your transaction, your rollback would undo the request's consumption and let
the same response be replayed, and your transaction would hold the connection's lock while the driver validates the
response.

The completion's transactions are its own. Only a provisioning listener opens one during a completion, on the same
connection, and has committed or rolled it back before it returns.

## Errors

A database error, a misconfigured contract and an issuer that throws propagate as server errors: they are never answered
as a failure redirect or a `400`, and they reach your exception handler as any other error does. A completion rolled
back by one leaves its request consumed, so the browser has to start again. A provisioning listener's exception is the
same: nothing resumes the completion, and a replay of the response is `request_unknown`.
