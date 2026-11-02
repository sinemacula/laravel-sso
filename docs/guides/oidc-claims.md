# OIDC Claims

This guide is for whoever sets up an OpenID Connect connection and reads what it verifies: whether to call the UserInfo
endpoint, what happens when it fails, where each value of the verified result comes from, how an email and its
`email_verified` travel together, and how claims are mapped. A connection's settings are in
[Managing connections](managing-connections.md#oidc-settings), and the callback in
[The OIDC Callback](oidc-callback.md).

## UserInfo on or off

UserInfo is off by default, and the ID token alone is then read: the provider is not called a second time.

Turn it on with `fetch_userinfo` when your provider leaves claims you need out of the ID token. The connection must then
name `userinfo_endpoint`, or it is incomplete. Turning it on or off is a trust change, as a change to an endpoint is.

```php
'settings' => [
    // ...
    'userinfo_endpoint' => 'https://idp.acme.example/oauth2/userinfo',
    'fetch_userinfo'    => true,
],
```

## UserInfo fails closed

While `fetch_userinfo` is on, UserInfo must answer: a completion never goes on with the ID token alone. There is one
attempt and no retry, within `sso.oidc.userinfo_timeout_seconds` (10 by default) and `sso.oidc.max_userinfo_bytes` (64
KiB by default), so a provider whose UserInfo endpoint is down stops sign-in through that connection. The request is
already consumed, so the person starts again.

| Error              | Why                                                                                  |
|--------------------|--------------------------------------------------------------------------------------|
| `fetch_refused`    | The endpoint's address is refused: see [Outbound Requests](outbound-requests.md)     |
| `fetch_failed`     | A timeout, a body over the cap, or a status outside `2xx` other than `401` and `403` |
| `provider_error`   | `401` or `403`, usually an access token that has expired or lacks a scope            |
| `userinfo_invalid` | The answer is signed or encrypted, is not a JSON object, or repeats a member         |
| `userinfo_invalid` | Its `sub` is not a string exactly equal to the ID token's                            |
| `userinfo_invalid` | A claim the package reads has the wrong type                                         |

A signed or encrypted answer (`application/jwt`) is not supported, so ask your provider for plain JSON.

`sub` is compared byte for byte: whitespace, case and Unicode form all count, and a number is not a string.

The package reads `email` (a string of at most 320 bytes), `email_verified` (`true` or `false`), and `name`,
`given_name` and `family_name` (strings). One of these with any other type refuses the answer, `null` included, since a
provider should leave out a claim it has no value for. A provider that sends `email_verified` as the string `"true"` is
refused. No other claim is judged.

On a `provider_error` the package logs a notice, `sso.oidc.userinfo_error`, with the connection's id, the request's
`request_reference` and the bearer token error code: `invalid_request`, `invalid_token` or `insufficient_scope`, or
`[unrecognized]` for anything else. The provider's description and the response's body are never logged, put in an event
or shown.

## Where each value comes from

| Value of the result                                        | Comes from                                              |
|------------------------------------------------------------|---------------------------------------------------------|
| `issuer`, `subject`                                        | The ID token, never UserInfo                            |
| `authenticationContext` (`auth_time`, `amr`, `acr`, `sid`) | The ID token, never UserInfo; unknown when it omits one |
| `assertedEmail`, `linkingEmail`                            | One source, as below                                    |
| `attributes`                                               | The connection's mapping, as below                      |

OIDC states no provider session deadline, so `providerSessionDeadline` is always `null`.

## The email and `email_verified`

An email and its `email_verified` are a pair from one source, never one from each:

1. the ID token, when it carries `email`, even when UserInfo has its own;
2. otherwise UserInfo, when it was fetched and carries `email`;
3. otherwise there is none.

`email_verified` is read from that same source, so UserInfo's flag never vouches for the ID token's email. When the
source does not state it, it stays unknown, which is not the same as false.

| The ID token says              | UserInfo says                | `assertedEmail`                       |
|--------------------------------|------------------------------|---------------------------------------|
| `a@acme.example`, verified     | anything                     | `a@acme.example`, `true`, `id_token`  |
| `a@acme.example`, not verified | `b@acme.example`, verified   | `a@acme.example`, `false`, `id_token` |
| `a@acme.example`, no flag      | `a@acme.example`, verified   | `a@acme.example`, `null`, `id_token`  |
| No email, verified             | `b@acme.example`, no flag    | `b@acme.example`, `null`, `userinfo`  |
| No email                       | `b@acme.example`, verified   | `b@acme.example`, `true`, `userinfo`  |
| No email                       | No email, or UserInfo is off | none                                  |

Read it from the verified result. The email is kept exactly as the provider sent it, and is shown only through
`email()`:

```php
$asserted = $result->assertedEmail;

$asserted?->email();    // The email, exactly as asserted
$asserted?->verified;   // true, false or null (unknown)
$asserted?->source;     // LinkingEmailSource::ID_TOKEN or ::USERINFO
```

`email_verified` is informational. Decide for yourself what your application does with it, and do not treat a provider's
`true` as proof that a person holds an address unless you trust that provider to verify it.

`linkingEmail` is the only value that lets a link be made by email. It is set only when the pair's `email_verified` is
exactly `true` and the email has one `@` between a local part and a domain, and it is never read from mapped attributes.

## Mapping claims

The connection's `attribute_mapping` reads from the ID token's claims with UserInfo's laid over them, so **UserInfo
wins** for a claim both state and the ID token's stands for a claim only it states. See [Managing
connections](managing-connections.md) for the mapping's rules and caps.

```php
// The ID token: {"name": "A Person", "given_name": "A"}
// UserInfo:     {"sub": "...", "name": "Ada Person", "family_name": "Person"}

$result->attributes; // ['given_name' => 'A', 'family_name' => 'Person', 'display_name' => 'Ada Person']
```

The one exception is `email`, which the mapping reads as the pair's, or finds absent when there is no pair, so under the
default mapping the mapped email and the asserted one never disagree. A mapping that reads the email from another claim
gets that claim's value, and `assertedEmail` is still the provider's `email`. A mapped email is profile data: it decides
`emailDomainVerified`, and never makes a link.

Protocol values and tokens are removed before the mapping reads anything, from both sources, and a mapping cannot name
them as a source: `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `auth_time`, `nonce`, `acr`, `amr`, `azp`, `at_hash`,
`c_hash`, `s_hash`, `sid`, `email_verified`, `access_token`, `id_token`, `refresh_token`, `code`, `state` and
`client_id`.

## Provider tokens

The provider's tokens are used only during the completion that received them. The access token is sent only to the
UserInfo endpoint, and nothing stores, returns, logs or puts in an event an ID token, access token or refresh token.
They never become your application's credentials, so your application cannot call the provider's APIs with them; if you
need that, run a separate authorisation with the provider.

The verified result is encrypted while a handoff code holds it. `json_encode()` of a result shows its `assertedEmail`
only as its source and flag, but it does show the mapped attributes and the linking email, so treat a result's JSON as
personal data and do not log it.
