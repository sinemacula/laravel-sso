# Provider Evidence for Further Factors

The verified result carries what the identity provider said about how the person authenticated: when, by which methods
(`amr`) and at what class (`acr`, or SAML's `AuthnContextClassRef`). The package never treats any of that as satisfying
your further factor. Whether a provider's assertion counts as evidence for it is your decision, per connection, and
until you make it nothing counts.

> A provider saying `mfa` is an input to your MFA policy, never an automatic pass. A value in `acr` or
> `AuthnContextClassRef` is the provider's own vocabulary, carried as data. Neither is an assurance level.

## Opting in

The contract's default, `InsufficientEvidence`, accepts nothing. Bind the package's policy to judge each connection's
stored policy:

```php
use SineMacula\Laravel\Sso\Contracts\EvidencePolicy;
use SineMacula\Laravel\Sso\Evidence\ConnectionEvidencePolicy;

$this->app->scoped(EvidencePolicy::class, ConnectionEvidencePolicy::class);
```

Then give each connection its policy, with `sso.connection.trust` freshness:

```php
use SineMacula\Laravel\Sso\Connections\EvidenceSettingsService;

$result = app(EvidenceSettingsService::class)->set($tenantId, $connectionId, [
    'amr'          => ['pwd', 'otp', 'hwk'],
    'acr'          => ['urn:example:loa:2'],
    'combinations' => [
        ['amr' => ['pwd', 'otp']],
        ['amr' => ['hwk'], 'acr' => 'urn:example:loa:2'],
    ],
]);
```

A SAML connection names `authn_context_class_ref` instead, and its combinations name one class each:

```php
$result = app(EvidenceSettingsService::class)->set($tenantId, $samlConnectionId, [
    'authn_context_class_ref' => ['https://refeds.org/profile/mfa'],
    'combinations'            => [
        ['authn_context_class_ref' => 'https://refeds.org/profile/mfa'],
    ],
]);
```

`set()` replaces the whole policy, and `set($tenantId, $connectionId, [])` clears it. `get($tenantId, $connectionId)`
reads it back. Who may call them is your authorisation. It answers a `ConnectionResult`:

| Outcome                            | When                                                    |
|------------------------------------|---------------------------------------------------------|
| `updated`, with `changedSettings`  | Names such as `evidence.amr`, sorted, and never a value |
| `unchanged`                        | The connection already holds it; nothing is written     |
| `invalid` (`settings_invalid`)     | `violations` name each path and code, and never a value |
| `refused` (`connection_not_found`) | No such connection in that tenant                       |
| `refused` (`freshness_required`)   | The caller's authentication is too old                  |
| `refused` (`protocol_unavailable`) | The connection's protocol is no longer available        |

A change reports `ConnectionUpdated` once, after commit. It is no trust change: nothing in flight is voided, no
reservation is touched, and a code already issued is judged at its redemption by the policy you just wrote.

## The policy

| Name                      | Protocol     | Holds                                                                        |
|---------------------------|--------------|------------------------------------------------------------------------------|
| `amr`                     | all but SAML | Accepted methods: at most 32, each once, each a value registered by RFC 8176 |
| `acr`                     | all but SAML | Accepted classes: at most 32, each once, 1 to 1024 bytes                     |
| `authn_context_class_ref` | SAML         | Accepted classes, as `acr`                                                   |
| `combinations`            | all          | What counts: 1 to 32 maps, any one of which is enough                        |

Each combination names `amr`, every one of whose methods the assertion must state, `acr`, the class it must state, or
both; or, on SAML, `authn_context_class_ref`. Everything it names must be in the accepted lists. Values compare exactly,
case included.

RFC 8176's values are `face`, `fpt`, `geo`, `hwk`, `iris`, `kba`, `mca`, `mfa`, `otp`, `pin`, `pwd`, `rba`, `retina`,
`sc`, `sms`, `swk`, `tel`, `user`, `vbm` and `wia`. Anything else your provider sends can never enter the evidence. If
it is what you rely on, rely on its class instead.

## How a result is judged

At redemption, with the policy the connection holds then, from the result's own assertion and nothing else. UserInfo and
any other assertion never strengthen it. It comes to `null`, never to a pass, and the redemption goes on without
evidence, when:

| Case                             | Detail                                                                                    |
|----------------------------------|-------------------------------------------------------------------------------------------|
| The policy is empty or malformed | A row the helper did not write counts as malformed                                        |
| No authentication time           | An ID token with no `auth_time`, say. Ask for it with the connection's `max_age`          |
| Too old                          | Older than `sso.linking.evidence_max_age_seconds` (60 to 3600, default 900) at redemption |
| Too far ahead                    | Later than the redemption by more than `sso.clock.skew_seconds`                           |
| No combination is satisfied      | Only accepted methods count towards one                                                   |

The handoff code's short lifetime establishes nothing. A code redeemed later than the maximum age, though unexpired, has
no evidence.

## What you receive

`$result->evidence` on the redemption's `RedemptionResult` (`$admission->evidence` if you redeem your own codes):

```php
$evidence = $result->evidence; // ?AcceptedEvidence

$evidence?->connectionId;      // the credential reference
$evidence?->authenticatedAt;   // when the provider authenticated the person
$evidence?->methods();         // only the accepted RFC 8176 methods, as asserted, each once
$evidence?->rawContext();      // the raw acr or AuthnContextClassRef, as data, listed or not
```

It is held for the request, and refuses to be serialised. A dump or `json_encode()` shows the connection, the time and
how many methods. Write what you need onto your session in the transaction that admits it (`completing-a-flow.md`,
`redeeming-a-handoff.md`): the connection and its tenant, the provider's authentication time and the evidence accepted.
Keep the sign-in's apart from what a later re-authentication gives, so renewing freshness never rewrites how the session
began.

| Purpose          | Asked                                            | What the evidence is                                                 |
|------------------|--------------------------------------------------|----------------------------------------------------------------------|
| `sign_in`        | Once an identity is established                  | Evidence of the first factor. An unlinked handoff has none           |
| `reauthenticate` | Once its exact link and bound session are judged | Evidence of this authentication alone; earlier evidence is unchanged |
| `link`           | Never                                            | None: a `link` proves nothing                                        |

## Under `laravel-iam`

The adapter maps accepted evidence to what `laravel-mfa` asked for:

| Purpose          | Proof                                                              |
|------------------|--------------------------------------------------------------------|
| `sign_in`        | `first_factor`                                                     |
| `reauthenticate` | `first_factor_reauthentication`, with MFA purpose `reauthenticate` |
| `link`           | no proof                                                           |

The connection's id is the credential reference. The evidence is offered to both the identity-level requirement
(AUTH-3.6) and the tenant's requirement (AUTH-2.12). Which factors combine, including the first factor's channel,
remains `laravel-mfa`'s policy or yours (AUTH-3.12).

## Writing your own policy

Implement `Contracts\EvidencePolicy` and answer `AcceptedEvidence` or `null`. Answer from the `VerifiedResult`'s
`authenticationContext` alone, and keep nothing between calls. It runs inside the redemption's transaction and under its
locks: do nothing slow, and let an error propagate, which rolls the redemption back with the code unconsumed.
