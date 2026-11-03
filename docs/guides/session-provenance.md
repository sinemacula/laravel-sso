# Session Provenance and the Authentication Context

A session your application starts from a redeemed `sign_in` handoff keeps a record of how it began: the connection and
its tenant, the protocol, when the provider authenticated the person, the evidence accepted at redemption, the exact
link and its provenance, the provider's session deadline and the cap it set, and the enforcement version. The package
captures that record for you, inside the redemption, and projects it on later requests into the `sso.*` keys of the
authentication context, so a policy can require "signed in through SSO" without depending on the package (SSO-9.7,
SSO-9.10).

## Capturing it

`RedemptionResult::$provenance` holds a `Sessions\Provenance` for an admitted `sign_in`, and `null` for anything else.
Write its `toArray()` with the session, in the same transaction as `admit()`, once. The sign-in route of the
[example application](example-application.md#signing-in-pending-sessions-and-no-credential-before-the-commit) admits
the code inside a transaction on `StorageConnection::name()` and writes the session there; with the session it writes:

<!-- snippet: tests/Integration/Examples/Routes/Application/SignIns.php#route-provenance-capture -->
```php
// Written once, with the session, in the redemption's transaction;
// never rewritten, not even by a re-authentication
$this->provenance[$sessionId] = $redemption->provenance?->toArray();
```

Your application keeps it in a JSON column of its session's own, say `sso_provenance`.

The package captures it from what the redemption admitted under its locks, never from what the provider asserted
alone:

- the methods (`amr`) and raw context class are those the evidence contract accepted at redemption; with nothing
  accepted, the methods are empty and the class is `null`, whatever the provider asserted ([Evidence](evidence.md));
- the link is the exact link admitted, and its provenance is the one it held under the redemption's locks: an activated
  verified domain reservation is `verified_domain`, and an existing link carries its own;
- the provider's raw session deadline is kept even when your `ProviderSessionDeadline` contract ignores it, in which
  case the cap (`session_not_after`) is `null`;
- the enforcement version is the one the redemption carried, and the tenant is the connection's at sign-in.

A `link`, a `reauthenticate`, a refused redemption and a standalone `redeem()` answer no provenance. That is what keeps
the record historical:

- a re-authentication renews the session's authentication time and leaves the stored provenance alone
  ([Re-authenticating](reauthenticating.md#what-a-renewal-changes));
- a later confirming `link` turns the link to `link_purpose`, but a session that began on a `verified_domain` link keeps
  `verified_domain`, since that is how it began. Only a new sign-in records the link as it now is.

An application that redeems handoff codes of its own through `HandoffRecheck::admit()`
([Redeeming codes of your own](redeeming-a-handoff.md#redeeming-codes-of-your-own)) captures the same record itself, in
the same transaction, from the `Admission` that call answers and what its code was bound to:
`Provenance::capture($result, $admission, $enforcementVersion, $sessionNotAfter)`, which is `null` for anything but a
passed `sign_in`.

Carry the stored array unchanged from a pending session to an active one, and across refreshes and switches of the
active tenant. Never rebuild it from the connection, the link or the evidence policy as they are now, and never rewrite
it after the session is created.

## Storing it

`toArray()` is the one durable form. It is versioned (`version` is `1`), every key is present with `null` where a fact
was not stated, instants are UTC strings to the microsecond (`2026-11-01T09:30:00.000000Z`), and the link's provenance
is its enum value. Keep it in a JSON column or any store that gives the same array back; the key order does not matter,
so a database that reorders JSON keys is fine.

`Provenance::restore()` reads it back, and refuses another version, a missing or unknown key, or any malformed value
with an `UnexpectedValueException`. Treat that as a server error, never as a session with no provenance.

Do not log or dump the stored array: it holds the accepted methods and raw context class. `json_encode()` of a
`Provenance` itself, and a dump of one, show the methods only as a count and the class only as `[redacted]`, so that
output is not the stored form. PHP's `serialize()` is refused.

## Projecting it

The example projects a session's stored provenance on a later request:

<!-- snippet: tests/Integration/Examples/Routes/Application/SignIns.php#route-provenance-project -->
```php
return AuthenticationContext::fromStored($this->provenance[$sessionId] ?? null);
```

A session with none (`null`) projects to no `sso.*` key. A policy that requires a connection compares
`$context[AuthenticationContext::CONNECTION] ?? null` with it.

`fromStored()` takes the stored array, or `null`, and `of()` takes a `Provenance`, or `null`. Both are pure: they read
nothing else and keep nothing.

| Key                                    | Type                        | Meaning                                                               |
|----------------------------------------|-----------------------------|-----------------------------------------------------------------------|
| `sso.connection`                       | string                      | The connection's opaque id                                            |
| `sso.tenant`                           | string                      | The connection's tenant at sign-in, never the current active tenant   |
| `sso.protocol`                         | string                      | The registered driver's name: `saml2`, `oidc` or your own             |
| `sso.provider_auth_time`               | UTC `CarbonImmutable`, null | When the provider authenticated the person                            |
| `sso.provider_amr`                     | list of strings             | The RFC 8176 methods accepted at sign-in; `[]` when none              |
| `sso.provider_acr`                     | string, null                | The accepted raw `acr` of any driver but `saml2`; data, never a level |
| `sso.provider_authn_context_class_ref` | string, null                | The accepted raw SAML `AuthnContextClassRef`; data, never a level     |
| `sso.link`                             | string, null                | The exact link admitted; `null` for an unlinked sign-in               |
| `sso.link_provenance`                  | string, null                | `link_purpose`, `provisioning`, `verified_domain` or `migration`      |
| `sso.provider_session_deadline`        | UTC `CarbonImmutable`, null | The provider's raw session deadline                                   |
| `sso.session_not_after`                | UTC `CarbonImmutable`, null | The cap that deadline set on your session, to the second              |
| `sso.enforcement_version`              | string, null                | The enforcement version the sign-in carried                           |

- **Absent versus null.** A session with no provenance from the package contributes no `sso.*` key at all. A session
  established through the package contributes every key, and a `null` value means that fact was not stated.
- **Types.** Every value is a string, a list of strings, `null` or a UTC `CarbonImmutable`; no type of the package
  crosses into the context. The provider's times keep their microseconds; `sso.session_not_after` is whole seconds.
- **What is never there.** The subject, the issuer, the provider session's id, an email, groups, mapped attributes and
  tokens are never captured or projected. Use `sso.connection` as the reference to the provider.
- **Stability.** The key names are the constants on `AuthenticationContext` and, with their meanings and types, are
  stable from 1.0.0.

> [!IMPORTANT]
> These keys say how the session began. They never replace a current check: revocation through
> `Contracts\SessionRevocation`, enforcement through `Contracts\Enforcement`, and freshness through
> `Contracts\Freshness` each judge current state, and a session that began compliantly can still be revoked by a later
> change.

## With `laravel-iam`

Under `laravel-iam`, its adapter does both halves: it writes the captured provenance with the session it starts through
`laravel-authentication`, and its authentication context contributor calls `AuthenticationContext::fromStored()` for the
`sso` namespace of AUTH-11.8. That namespace is this package's: `laravel-authentication` exposes the session's
provenance for reading and never writes into it (its authentication context, BL-106 there, is planned and not yet
built).

The provenance `laravel-authentication` keeps per session, as observed on its branch `feat/sso-seams` at `caa595f`
(unreleased, `Proofs\Provenance`), holds the connection, the tenant, the provider's authentication time to the whole
second, one session deadline, the policy version, the link id and accepted evidence. It has no field for the protocol,
the link's provenance or the provider's raw deadline as distinct from the cap, and it drops microseconds. So the
adapter keeps `toArray()` whole beside it, written once with the session, and projects from that, rather than
reconstructing the record from the narrower fields. See
[Integrating with `laravel-iam`](integrating-with-laravel-iam.md).
