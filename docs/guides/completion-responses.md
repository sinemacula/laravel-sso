# Completion Responses

When an identity provider sends the browser back to your API, at a connection's assertion consumer service (SAML) or
its callback (OIDC), the completion helper answers a `CompletionResult`: how the completion ended. The package has no
routes: your controller turns that result into the response, and `CompletionResponses` builds it for you, so every
completion answers with the right status, the right redirect and the right headers.

## The controller

`SineMacula\Laravel\Sso\Responses\CompletionResponses::from($result, $method)` answers a
`SineMacula\Laravel\Sso\Responses\CompletionResponse`, which Laravel sends as it is when a controller returns it. Pass
the method the completion arrived by: it decides the redirect's status.

With the example route layout (SSO-12.5):

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

[Completing a flow](completing-a-flow.md) explains what the completion helper checks and when each result is answered.

These routes take no session, no CSRF token and no authentication: the identity provider's response is checked by the
completion itself. Put them outside the `web` middleware group, or exclude them from CSRF verification, since a SAML
response is a cross-site POST.

## What each outcome answers

| Outcome        | Status                                         | `Location`                                      | Body                                          |
|----------------|------------------------------------------------|-------------------------------------------------|-----------------------------------------------|
| `completed`    | `303` after a POST, `302` after a GET          | your redirect URI with `code` and `reference`   | `completion.redirecting`                      |
| `failed`       | `303` after a POST, `302` after a GET          | your redirect URI with `error` and `reference`  | `completion.redirecting`                      |
| `reinitiated`  | `303` after a POST, `302` after a GET          | the connection's start URL, exactly as set      | `completion.redirecting`                      |
| `rejected`     | `400`                                          | none                                            | `completion.invalid`                          |
| `rate_limited` | `429`, with `Retry-After` in seconds           | none                                            | `completion.invalid`                          |

Any other method (`HEAD`, say) is answered with a `303`. A completion never answers with a `307` or a `308`, which
would make the browser post the SAML response again, to your redirect URI.

- **Completed**: a handoff code was issued. Your client redeems it with its verifier.
- **Failed**: the flow failed after its authorisation request was found, so your redirect URI is trusted. `error` is a
  failure reason's code (`request_expired`, `signature_invalid`, `enforcement_unsatisfied` and so on), never a reason
  in prose or the identity provider's description: word it yourself, in your client's translations.
- **Rejected**: no trusted redirect target is known (an unknown connection, or a response that matches no
  authorisation request), so the browser stays on the API with a `400`.
- **Rate limited**: a completion limit is full.
- **Re-initiated**: an unsolicited SAML response from a connection that allows it; the browser goes to the start URL
  set on the connection, which starts a fresh flow.

Every response, the `400` and the `429` included, is sent with `Cache-Control: no-store`, `Referrer-Policy:
no-referrer` and `Content-Type: text/plain; charset=UTF-8`. Symfony writes the first as `no-store, private`.

The bodies are the package's messages, in the current locale, so set the locale before you build the response if your
API chooses one per request. Change their wording or translate them as the [localisation guide](localization.md)
shows: the keys are `sso::messages.completion.redirecting` and `sso::messages.completion.invalid`. The body of a
`400` is the same whatever went wrong, so it tells nobody why.

## Where the code goes

The parameters are appended to your application's redirect URI exactly as you configured it: no path, trailing slash
or anything else is added, and a native application's private-use scheme is kept. Each application's `delivery`
setting (`sso.applications.<name>.delivery`) says where:

```text
fragment (the default)  https://app.example.com/sso#code=…&reference=…
                        com.example.app:/sso#code=…&reference=…
query                   https://app.example.com/sso?code=…&reference=…
query, after a query    https://app.example.com/sso?tenant=acme&code=…&reference=…
a failure, either way   https://app.example.com/sso#error=request_expired&reference=…
```

`code` (or `error`) comes first, then `reference`. Every value is base64url or a lower-case code, so none needs
decoding, but read them with a URL parser all the same.

Keep the fragment unless your client cannot read one. A fragment never reaches a server, a proxy's access log or a
`Referer` header; a query reaches your web server's logs and anything the page at your redirect URI loads.

## What your client does with the fragment

At your redirect URI, the client:

1. Reads the parameters from the fragment, and then removes the fragment from the address bar, so the code is not
   kept in the history or shared with the URL.
2. Checks that `reference` is the reference its start returned, and finds the verifier it kept for it (the package
   carries no return URL; keep yours keyed by the same verifier or reference).
3. On `code`, redeems it at once (it lives for 60 seconds by default, and only once) with the application, the
   connection and the verifier. On `error`, shows its own words for the code, and may show the reference for support.

```js
const parameters = new URLSearchParams(window.location.hash.slice(1));

history.replaceState(null, '', window.location.pathname + window.location.search);

const reference = parameters.get('reference');
const pending = JSON.parse(sessionStorage.getItem(`sso:${reference}`) ?? 'null');

sessionStorage.removeItem(`sso:${reference}`);

if (pending === null) {
    // No sign-in was started here with this reference: ignore the response.
} else if (parameters.has('code')) {
    await fetch('/auth/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            application: pending.application,
            connection: pending.connection,
            code: parameters.get('code'),
            verifier: pending.verifier,
        }),
    });
} else {
    showSignInError(parameters.get('error'), reference);
}
```

A native application receives the whole URL, fragment included, from the operating system through its registered
scheme, and reads it the same way.

With query delivery, the page at your redirect URI receives the code in its own request: keep it out of your access
logs, and send `Referrer-Policy: no-referrer` from that page as well.

## Errors

`CompletionResponses` catches nothing. A database error during a completion is a server error (SSO-11.4): the
completion never answers it as a result, so it never becomes a failure redirect, and it reaches your exception handler
as a `500`. Do not catch it to send the browser to your redirect URI with an `error`: a refused sign-in and an outage
are different things, and only the first is the person's to act on.

## Logging and debugging

A `CompletionResponse` holds its `Location`, which carries the handoff code, wrapped: dumping it or encoding it as JSON
shows the `Location` with the code as `[redacted]`, and serialising it throws. `location()` reveals it; read it only to
send it. The reference is the one flow identifier safe to log.
