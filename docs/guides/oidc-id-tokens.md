# OIDC ID Tokens

This guide is for whoever sets up an OpenID Connect connection and has to work out why a sign-in failed: which signature
algorithms to allow, what trusted audiences and `max_age` do, and what each failure code means. Every check here is
always on, and none can be turned off. A connection's settings are in
[Managing connections](managing-connections.md#oidc-settings), the callback in [The OIDC Callback](oidc-callback.md),
and keys and their refresh in [Setting Up An OIDC Connection](oidc-connections.md).

## Algorithms

`id_token_algorithms` lists what your provider may sign ID tokens with. It defaults to `RS256`.

```php
'settings' => [
    // ...
    'id_token_algorithms' => ['RS256', 'ES256'],
],
```

Allow only what your provider uses. `RS256` to `RS512`, `PS256` to `PS512` and `ES256` to `ES512` can be listed; `none`
and every `HS*` cannot. A token signed with an algorithm off the list is refused with nothing fetched, whatever key it
names. Each `ES*` algorithm needs a key on its own curve: P-256 for `ES256`, P-384 for `ES384`, P-521 for `ES512`. An
RSA key needs at least 2048 bits. A key your provider publishes that does not meet this is left out of the connection's
JWKS.

Changing the list is a trust change, so flows in flight through the connection are voided.

## Which key signs a token

The key is the one in the connection's stored JWKS whose `kid` is exactly the token's. A token with no `kid` is checked
with the only key that fits its algorithm, and is refused when two could. A `jku`, `x5u`, `jwk` or `x5c` in a token's
header is ignored: a key only ever comes from the JWKS. [The refetch cooldown](oidc-connections.md#the-refetch-cooldown)
explains what happens when a token names a `kid` the connection does not hold.

## Trusted audiences

An ID token's `aud` must hold your connection's `client_id`. By default nothing else may appear in it. If your provider
adds another audience, such as an API, list it:

```php
'settings' => [
    // ...
    'trusted_audiences' => ['https://api.acme.example'],
],
```

Three rules go with it:

- Audiences are compared exactly, so case and whitespace count.
- A token with more than one audience must carry `azp`, and `azp`, when present, must be your `client_id`. A provider
  that adds an audience and leaves out `azp` is refused, however much you trust the audience.
- A trusted audience never replaces your `client_id`: a token for your API alone is not for this connection.

Only add an audience you know the provider adds for you. An unexpected one usually means the token was issued to another
client.

## `max_age`

Set `max_age` when a sign-in must follow a recent authentication at the provider. It is sent on every authorisation
request, in seconds from 0 to a week, and the ID token must then carry `auth_time`. A positive `max_age` is an age: no
older than it plus the clock skew when the callback runs. A `max_age` of 0 asks the provider to authenticate afresh, and
is held to the request instead.

```php
'settings' => [
    // ...
    'max_age' => 3600,
],
```

Some providers only send `auth_time` when asked, and `max_age` asks. A provider that ignores it has its sign-ins refused
with `id_token_invalid`, which fails closed: check your provider's documentation before turning it on.

A `reauthenticate` always asks for `max_age` 0 and `prompt=login`, whatever the connection's `max_age`. Its `auth_time`,
like that of any `max_age` of 0, must be no earlier than when the flow started, less the skew, and not past now plus the
skew. It is judged relative to the request, never to the callback: a person who authenticated for this request and took
minutes to come back still passes, as long as the token's own `exp` and `iat` do. A positive `max_age` on the connection
still applies to a `reauthenticate`, measured from now.

## Times and the clock skew

The clock skew is `sso.clock.skew_seconds` (60 seconds by default, at most 300). It is allowed on `exp`, `iat`, `nbf`
and `auth_time`. `iat` must also be within `sso.oidc.id_token_max_age_seconds` (300 seconds by default) of now, plus the
skew. A sign-in that fails with `assertion_expired` on every attempt usually means your server's clock or the provider's
has drifted further than the skew: fix the clock rather than raising the skew.

## Troubleshooting

Each failure is redirected to your application's redirect URI with its code and the request's public reference. The
request stays consumed, so the person starts again. Checks run in a fixed order and the first failure answers, so a
token with two problems reports the earlier: fixing it may reveal the next.

| Failure code             | What it means                                                                                                          | What to check                                                                            |
|--------------------------|------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------|
| `id_token_invalid`       | Not a compact signed token, over the size cap, or a claim of the wrong type or missing                                 | Encrypted ID tokens are not supported                                                    |
| `id_token_invalid`       | `auth_time` missing while `max_age` or a `reauthenticate` asked for it                                                 | Whether your provider returns `auth_time`; remove `max_age` if it cannot                 |
| `signature_invalid`      | The algorithm is off the allow-list, no stored key is the token's, or the signature does not verify                    | `id_token_algorithms`; the JWKS URL; `JwksRefreshFailed` events for a failed refetch     |
| `issuer_mismatch`        | `iss` is not exactly the connection's issuer                                                                           | A trailing slash or a different path in `issuer`; `iss` is compared byte for byte        |
| `audience_mismatch`      | `aud` lacks the `client_id`, holds an untrusted audience, has several with no `azp`, or `azp` differs                  | `client_id`, `trusted_audiences`, and whether the provider sends `azp`                   |
| `assertion_expired`      | `exp` has passed, `iat` is too old or in the future, `nbf` or `auth_time` is in the future                             | The clocks on your servers and the provider's; a token held too long before the callback |
| `nonce_mismatch`         | `nonce` is missing or is not the one this flow sent                                                                    | A provider that drops `nonce`; a callback replayed from another flow                     |
| `authentication_expired` | `auth_time` is older than a positive `max_age`, or earlier than the request for a `max_age` of 0 or a `reauthenticate` | A provider's session reused without a new sign-in; whether it honours `prompt=login`     |
| `at_hash_mismatch`       | `at_hash` is not the hash of the access token                                                                          | A token endpoint returning an access token from another exchange                         |
| `connection_unavailable` | The connection changed while the sign-in was in progress, whether or not the token passed                              | A disable, a trust change, or another sign-in's key rotation; the person starts again    |

A key your provider removed or replaced voids every other flow in flight and every handoff code not yet redeemed, and
those people see `connection_unavailable` and start again. The one sign-in whose token found the rotation may finish,
unless something else changes before its final locks. Providers that publish the new key well before retiring the old
one cause none of this.

The provider's tokens are never logged, put in an event, stored or shown, and neither is a provider's error description.
When you need the detail of a failure, read the provider's own logs by the time and the client id, and search your logs
and events by the request's `request_reference`.
