# The OIDC Callback

This guide is for whoever sets up an OpenID Connect connection and the route the identity provider sends the browser
back to: the callback route, how the response's `iss` is checked, what becomes of an error, and how to set up each
client authentication. The steps every completion runs are in [Completing a Flow](completing-a-flow.md), and a
connection's settings in [Managing connections](managing-connections.md#oidc-settings).

## The callback route

The package has no routes of its own. Add a `GET` route at the connection's callback, and hand the request to the
completion helper:

```php
Route::get('/auth/sso/connections/{connection}/callback', [SsoCompletionController::class, 'callback']);
```

```php
public function callback(Request $request, string $connection): CompletionResponse
{
    $result = $this->completions->callback($connection, CompletionRequest::fromRequest($request));

    return $this->responses->from($result, $request->getMethod());
}
```

Register the URL `EndpointResolver` gives for the connection as the redirect URI at the provider. It is built from
`sso.endpoints` and the connection's id, never from the request's host or headers, and it is sent as `redirect_uri` on
both the authorisation request and the token request, so it must match what the provider holds exactly.

Call the helper outside any transaction on the package's storage connection. Inside one it throws a `LogicException`
before it writes or sends anything.

## What is refused before anything is read

The callback reads the raw query string, not Laravel's parsed one, so use `CompletionRequest::fromRequest()`, which
keeps it. Before any request is looked up, the whole query is refused when:

- a parameter repeats, even with the same value, or once percent-decoded;
- a name is shaped as an array (`state[]`, `code[x]`);
- a name or value is longer than `sso.oidc.max_callback_parameter_bytes` (2 KiB by default), the query longer than
  `sso.oidc.max_callback_query_bytes` (8 KiB) or there are more than `sso.oidc.max_callback_parameters` parameters (16);
- a name or value is not valid UTF-8 or holds a control character;
- `state` is missing or not the package's own form, exactly 43 base64url characters.

Such a callback answers `request_unknown` with a `400` and no redirect, since no request names a trusted redirect
target, and nothing is consumed. A parameter the package does not read is otherwise ignored. A response posted to the
callback (`response_mode=form_post`) is refused the same way: only `GET` is accepted.

## The `iss` parameter

Once its request is consumed, the response's `iss` (RFC 9207) is checked before anything else in it, so before it is
handled as a success or an error:

- when present, it must equal the issuer the request recorded, byte for byte: a trailing slash or another case is
  `issuer_mismatch`;
- when absent, it is `issuer_mismatch` if the request says the provider returns it: the provider's metadata sets
  `authorization_response_iss_parameter_supported`, or the connection's `returns_iss` setting is on;
- when absent otherwise, the response is accepted only at the callback of the request's own connection.

A response carrying another connection's `state` is `connection_mismatch`, and its failure goes to that request's
application. Neither provider is sent anything. Together these are the defence against mix-up attacks (RFC 9700 §4.4.2).

If your provider returns `iss`, turn `returns_iss` on: without it, a response that omits `iss` is accepted on its
connection's callback alone.

## Errors

| The provider answers                                    | The failure code         |
|---------------------------------------------------------|--------------------------|
| `error` alone                                           | `provider_error`         |
| `error` with `code`, neither, or an empty `code`        | `response_invalid`       |
| a token endpoint `400` or `401` with an OAuth `error`   | `provider_error`         |
| a token endpoint `5xx`, redirect or other status        | `fetch_failed`           |
| a timeout, or a response over the cap                   | `fetch_failed`           |
| a token endpoint the fetcher refuses to reach           | `fetch_refused`          |
| a body that is not a JSON object, or repeats a member   | `token_response_invalid` |
| no `id_token`, or an empty one                          | `id_token_invalid`       |
| no valid `access_token`, or a `token_type` not `Bearer` | `token_response_invalid` |

Each is redirected to your application's redirect URI with its code and the request's public reference, and the browser
has to start again: the request stays consumed whatever happens, and the token request is made once and never retried.

The provider's `error` is logged only as a code, under `sso.oidc.callback_error` or `sso.oidc.token_error`, with the
connection and the request's reference. `error_description` and `error_uri` are never logged, evented or shown, and
neither is a token: read the provider's own logs for the detail, by the time and the client id.

## Client authentication

A connection authenticates at the token endpoint by exactly one method, its `client_authentication` setting. A
connection missing its credential is not usable, so its callbacks answer `connection_unavailable`.

### `client_secret_basic` (the default) and `client_secret_post`

Register the same method at the provider, and give the secret with the settings:

```php
$connections->update($tenantId, $connectionId, ['settings' => [
    'client_id'             => 'the-client-id',
    'client_authentication' => 'client_secret_post',
    'client_secret'         => $secret,
]]);
```

The secret is encrypted at rest and never shown again. Rotating it is a trust change: flows in flight through the
connection are voided, and a completion waiting on the token endpoint is refused `connection_unavailable`.

### `private_key_jwt`

The connection signs an RFC 7523 client assertion for each token request with its own key, so no secret is shared:

1. Turn on `client_authentication` `private_key_jwt`, then add a key with
   `KeyService::addNext($tenantId, $connectionId, KeyUse::CLIENT_ASSERTION)` and make it current with `makeCurrent()`
   (see [Keys](keys.md)).
2. Register the connection's public JWKS at the provider.
3. Give the provider's token endpoint as the audience it expects. The assertion's `aud` is the connection's
   `token_endpoint` setting, exactly as you saved it, with `iss` and `sub` the client id, a `jti` used once and a
   lifetime of 60 seconds, signed `PS256` for an RSA key and `ES256` for an elliptic curve key.

## Limits

| Setting                                 | Default | What it decides                           |
|-----------------------------------------|---------|-------------------------------------------|
| `sso.oidc.max_callback_parameter_bytes` | 2 KiB   | The longest decoded name or value         |
| `sso.oidc.max_callback_query_bytes`     | 8 KiB   | The longest raw query                     |
| `sso.oidc.max_callback_parameters`      | 16      | The most parameters in a query            |
| `sso.oidc.token_timeout_seconds`        | 10      | The whole time the token request may take |
| `sso.oidc.max_token_response_bytes`     | 64 KiB  | The largest token response                |

The token request goes through the package's fetcher, so the connection's `token_endpoint` must be a public `https`
address, and it follows no redirect.

## Events

A completed callback reports `ResultVerified` then `HandoffIssued`. A callback refused before its request is consumed
reports one `FlowFailed` with no `request_reference`, and one refused afterwards one `FlowFailed` with it. No event or
log carries a provider token, the code, the state, the verifier or the provider's description.
