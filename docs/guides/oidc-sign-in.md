# Signing In with OIDC

This guide is for whoever builds sign-in through an OpenID Connect connection: what a start sends to the provider, what
your client must do, and how reauthentication works. Starting any flow, the answer's shape and the refusals are
described in [Starting a Flow](starting-a-flow.md); completing it in your API in
[Completing a Flow](completing-a-flow.md); setting a connection up in
[Setting Up An OIDC Connection](oidc-connections.md), and its settings in
[Managing connections](managing-connections.md#oidc-settings).

## Starting a flow

You start an OIDC flow as any other, through `AuthorizationRequestService`:

```php
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;

$result = app(AuthorizationRequestService::class)->start(
    application: 'web',
    purpose: Purpose::SIGN_IN,
    connectionId: $connectionId,
    codeChallenge: $codeChallenge,
);

return response()->json($result->body(), $result->isStarted() ? 200 : 400, $result->headers());
```

A started answer's `navigation` is a `redirect`: send the top-level window to its `url`. A start makes no call to the
provider, so it cannot fail because the provider is down.

## What the provider is sent

The browser is sent to the connection's authorisation endpoint with these parameters, in this order, encoded per
RFC 3986:

| Parameter               | What it carries                                                                         |
|-------------------------|-----------------------------------------------------------------------------------------|
| `response_type`         | `code`: the authorisation code flow is the only one the package uses                    |
| `client_id`             | The connection's client id                                                              |
| `redirect_uri`          | The connection's callback, built from `sso.endpoints` and never from a request          |
| `scope`                 | The connection's `scopes`, joined by single spaces                                      |
| `state`                 | A random value of the flow, never the request's public reference                        |
| `nonce`                 | A random value of the flow, which the ID token must return                              |
| `code_challenge`        | The S256 challenge of a verifier the package keeps                                      |
| `code_challenge_method` | `S256`                                                                                  |
| `max_age`               | The connection's `max_age` when it has one, or `0` for a reauthentication               |
| `prompt`                | `login` for a reauthentication                                                          |
| the extra parameters    | The connection's `extra_parameters`, as stored                                          |

Register the callback at the provider exactly: `redirect_uri` is compared byte for byte, there and at the token
endpoint. No `response_mode` is sent, so the provider answers in the query string, the only way the callback accepts.

The request keeps only the digests of `state` and `nonce`, the verifier encrypted, the connection's issuer and trust
version, and whether the provider must return `iss`. Turn `returns_iss` on when your provider returns it; importing a
discovery document that advertises it does this for you, and from then on a response without `iss` is refused.

## Extra parameters

`extra_parameters` may set `prompt`, `acr_values`, `login_hint`, `ui_locales`, `claims_locales`, `display`,
`domain_hint` and `hd`. A parameter the flow controls can never be set this way: the settings refuse it, and the start
leaves it out in any case. The extra parameters are the connection's, sent with every request through it, so put nothing
there that belongs to one person.

An authorisation endpoint may carry a query of its own, such as a tenant or a policy, and it is kept. If that query
names a parameter the request sets, in any case, the start is refused with `connection_unavailable` rather than sending
it twice or overriding it: move the value to `extra_parameters`, or remove it.

## The client's duties

Your client's duties are those of every flow, listed in [Starting a Flow](starting-a-flow.md#the-clients-duties):
generate a fresh verifier per request (or let the package generate it), keep it with the request's public reference,
redeem only a handoff whose reference it started, send the code and the verifier in a POST body, and remove the code
from the address bar at once.

The verifier your client holds is not the one the provider sees. The package keeps its own PKCE verifier for the token
request, which never leaves your API, and the two are independent: a client's `code_challenge` is never sent to the
provider. Do not read `state`, `nonce` or `code_challenge` from the navigation's URL, and do not log the URL: it carries
the flow's values, which is why every dump of the navigation redacts them.

Trust changes reach the flow: a client secret or a JWKS URL updated while a start is under way refuses the start with
`connection_unavailable`, or voids its request if it had already been stored. Your client treats that like any other
refusal, and starts again.

## Reauthentication

A `reauthenticate` start is for an identity already signed in through the connection, on one session. It forces fresh
authentication at the provider, whatever the connection configures:

- `max_age=0` is sent in place of the connection's `max_age`;
- `prompt=login` is sent, and an extra `prompt` is left out.

Bind `Contracts\ReauthenticationSessions`, which says whether the identity is signed in through the connection on the
session: by default the package keeps no sessions, so every `reauthenticate` is refused with `session_ineligible`. Take
the identity and the session from your own authentication, never from the request body:

```php
$result = app(AuthorizationRequestService::class)->start(
    application: 'web',
    purpose: Purpose::REAUTHENTICATE,
    connectionId: $connectionId,
    codeChallenge: $codeChallenge,
    identity: $identity,
    sessionId: $sessionId,
);
```

A provider that ignores `prompt` or `max_age` is caught when the flow completes: the ID token's `auth_time` must be no
earlier than the request, within the clock skew. Reauthentication proves fresh authentication and nothing else; see
[Starting a Flow](starting-a-flow.md#purposes).

## Failures

| Error                    | Why                                                                                     |
|--------------------------|-----------------------------------------------------------------------------------------|
| `connection_unavailable` | Disabled, incomplete, changed while starting, or its endpoint's query names a parameter |
| `metadata_expired`       | A refresh validated the discovery document or the JWKS longer ago than the limit        |
| `freshness_required`     | A `link` from a caller who did not authenticate recently enough                         |
| `session_ineligible`     | A `reauthenticate` for an identity not signed in through the connection on the session  |

A connection is incomplete without its settings, without its client secret, or for `private_key_jwt` without a current
`client_assertion` key.

Each refusal stores nothing and reports one `FlowFailed` event with the reason. A started flow reports
`AuthorizationRequestStarted` once it commits, naming the request's public reference and never its `state`, `nonce` or
challenge. See [Events](events.md).
