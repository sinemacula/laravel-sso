# Session Provenance and the Authentication Context

## Purpose

This note describes how the package records how a session began and what it contributes to a request's authentication
context (SSO-9.7, SSO-9.10). There are two separate operations:

- **Capture**: inside the transaction of a successful `sign_in` redemption, the package builds an immutable
  `Sessions\Provenance` from what that redemption admitted, and answers it on the redemption result. The adapter writes
  it with the session, once.
- **Project**: on any later request, `Sessions\AuthenticationContext` reads the provenance the session stored and
  answers the `sso.*` keys. It is a pure function of that stored value.

What is prohibited is the third thing: rebuilding historical provenance from the connection, link or evidence policy as
they are today. The guide is `docs/guides/session-provenance.md`.

## Invariants

- Provenance is captured from the **admitted redemption**, never from the verified result alone. The result carries what
  the provider asserted; the admission carries what was accepted under the redemption's locks: the evidence the evidence
  contract accepted at redemption, the exact link admitted and that link's provenance, and the version of the
  enforcement the connection was judged by under those locks, alongside the effective session cap the code was bound to.
  The session keeps that version, never the one the completion checked (which no code keeps), since a rule may change
  between the two and the redemption's is the one the session was admitted under
  ([RD-34](requirements.md#recorded-decisions)).
- Only an admitted `sign_in` captures provenance. `Provenance::capture()` answers `null` for a `link`, a
  `reauthenticate` or an admission that did not pass, and `HandoffRedemption` captures nothing outside the caller's
  transaction. So no later operation of the package yields a value that could overwrite how a session began: a
  re-authentication renews the session's authentication time through
  `ReauthenticationSessions::renewAuthentication()` and nothing else, and a confirming `link` changes the link row, not
  any session's captured provenance.
- The link's provenance is carried out of the locked admission, never fetched afterwards. For a link that existed, the
  package's link store states it on the resolution its `sign_in` branch judged under the connection's lock
  (`LinkResolution::$origin`), the branch's `Judgement` carries it to the admission, and the `Admission` carries it
  out. For a reservation activated at redemption, the activation answers the provenance it gave the row
  (`verified_domain`). A linker that does not state it leaves it `null`.
- The provider's raw session deadline and the effective cap it set on the application's session are both kept. They
  differ when `Contracts\ProviderSessionDeadline` answers `ignored`: the raw deadline is kept and the cap is `null`.
- Only accepted evidence supplies methods and a raw context class. With no evidence accepted, `provider_amr` is empty
  and both raw context keys are `null`, whatever the provider asserted. The raw class is kept as SAML
  `AuthnContextClassRef` for the package's `saml2` driver and as `acr` for every other driver, which is how the evidence
  policy reads them (`evidence.md`). Neither is ever an assurance level.
- Nothing about the person or their provider session is captured or projected: never the subject, the issuer, the
  provider session's id, an email, groups, a mapped attribute or a token. The connection's id is the policy reference.
- The keys are historical. They never stand in for a current check of revocation, enforcement or proof freshness:
  enforcement is judged by the enforcement contract and the revocation contract, and freshness by the freshness
  contract, each against current state.

### The stored form

`Provenance::toArray()` is the one durable form, version 1:

| Key                                | Type             | Meaning                                                     |
|------------------------------------|------------------|-------------------------------------------------------------|
| `version`                          | integer          | `1`                                                         |
| `connection_id`                    | string           | The connection's opaque id                                  |
| `tenant_id`                        | string           | The connection's tenant at sign-in                          |
| `protocol`                         | string           | The registered driver's name                                |
| `provider_auth_time`               | string or `null` | When the provider authenticated the person                  |
| `provider_amr`                     | list of strings  | The RFC 8176 methods accepted at redemption; `[]` when none |
| `provider_acr`                     | string or `null` | The accepted raw `acr` of any driver but `saml2`            |
| `provider_authn_context_class_ref` | string or `null` | The accepted raw SAML `AuthnContextClassRef`                |
| `link_id`                          | string or `null` | The exact link admitted; `null` for an unlinked admission   |
| `link_provenance`                  | string or `null` | That link's `Links\Enums\LinkOrigin` value as admitted      |
| `provider_session_deadline`        | string or `null` | The provider's raw session deadline                         |
| `session_not_after`                | string or `null` | The effective cap on the session; `null` when none was set  |
| `enforcement_version`              | string or `null` | The enforcement version judged under the redemption's locks |

Every key is present; `null` means the fact was not stated. Instants are UTC strings to the microsecond
(`Y-m-d\TH:i:s.u\Z`); `session_not_after` carries whole seconds, since the handoff code keeps its cap to the second.
`Provenance::restore()` reads exactly this form, in any key order, and refuses another version, a missing or unknown
key, or any malformed value with an `UnexpectedValueException`; it never reads one as no provenance. A change to the
stored form takes a new version number, and the package goes on reading version 1, whose keys, meanings and types never
change.

The stored form is plain: a map with string keys, the version an integer and every other value a string, `null` or a
list of strings, two arrays deep. Each part keeps to the domain a capture can produce, refused otherwise at
construction and on restore:

| Part                                                 | Domain                                                                      |
|------------------------------------------------------|-----------------------------------------------------------------------------|
| `connection_id`                                      | 1 to 64 bytes (`MAX_CONNECTION_ID_LENGTH`) of printable ASCII               |
| `tenant_id`                                          | 1 to 255 bytes (`MAX_ID_LENGTH`) of valid UTF-8, any characters             |
| `protocol`                                           | a driver's name (`ProtocolManager::NAME_PATTERN`), at most 64 bytes         |
| `provider_amr`                                       | RFC 8176's registered values (`EvidenceRules::RFC_8176_METHODS`), each once |
| `provider_acr` or `provider_authn_context_class_ref` | 1 to 255 bytes (`MAX_CONTEXT_LENGTH`) of printable ASCII, at most one       |
| `link_id`                                            | 1 to 255 bytes (`MAX_ID_LENGTH`) of printable ASCII                         |
| `enforcement_version`                                | 1 to 64 bytes (`MAX_VERSION_LENGTH`) of printable ASCII                     |

Printable ASCII is space to tilde (`0x20` to `0x7E`). The tenant id is the application's own opaque id, so it is not
restricted to ASCII; it must be valid UTF-8, since no other string is encodable as JSON. `capture()` never fails a
sign-in on what a provider or an evidence policy gave: it keeps only the registered methods of the accepted evidence,
in their order and each once, and keeps a raw context class outside its domain as `null`, since both are data, never a
decision.

So the stored form, encoded as JSON with the default escaping (`json_encode()` with `JSON_THROW_ON_ERROR` and
`JSON_PRESERVE_ZERO_FRACTION`, the flags a sibling's provider context encodes with), always takes at most
`MAX_STORED_JSON_BYTES` (4,096). JSON's default escaping takes at most two bytes for a byte of printable ASCII (`"`,
`\` and `/`) and at most six for a byte of any UTF-8 (a control character as `\u0001`; a character outside ASCII as
one or two `\uXXXX`, at most three times its bytes). With every part at its limit and of those characters:

| Key and value                                                     | Bytes |
|-------------------------------------------------------------------|------:|
| `"version":1`                                                     |    11 |
| `"connection_id":` and 64 bytes, each escaped to 2, quoted        |   146 |
| `"tenant_id":` and 255 bytes, each escaped to 6, quoted           | 1,544 |
| `"protocol":` and 64 bytes, unescaped, quoted                     |    77 |
| `"provider_auth_time":` and a 27-character instant, quoted        |    50 |
| `"provider_amr":` and all 20 registered methods                   |   141 |
| `"provider_acr":` and 255 bytes, each escaped to 2, quoted        |   527 |
| `"provider_authn_context_class_ref":null` (the other raw context) |    39 |
| `"link_id":` and 255 bytes, each escaped to 2, quoted             |   522 |
| `"link_provenance":"verified_domain"`, the longest                |    35 |
| `"provider_session_deadline":` and an instant                     |    57 |
| `"session_not_after":` and an instant                             |    49 |
| `"enforcement_version":` and 64 bytes, each escaped to 2, quoted  |   152 |
| The braces and twelve commas                                      |    14 |
| **Total**                                                         | 3,364 |

That leaves 732 bytes (about 18%) under 4,096. The raw class in `provider_authn_context_class_ref` instead takes the
same. `StoredProvenanceTest` builds exactly that provenance, asserts the 3,364 bytes and the plain values, and asserts
each part at its limit and every stored key named, so a key added or a limit loosened fails it.

`json_encode()` and a dump show the methods as a count and each raw context as `[redacted]`, so their output is not the
stored form. PHP serialisation is refused, since a serialised object is tied to the class rather than to the versioned
form.

### The projection

`AuthenticationContext::of(?Provenance)` and `fromStored(?array)`:

| Key                                    | Type                         | From                               |
|----------------------------------------|------------------------------|------------------------------------|
| `sso.connection`                       | string                       | `connection_id`                    |
| `sso.tenant`                           | string                       | `tenant_id`                        |
| `sso.protocol`                         | string                       | `protocol`                         |
| `sso.provider_auth_time`               | string (UTC instant) or null | `provider_auth_time`               |
| `sso.provider_amr`                     | list of strings              | `provider_amr`                     |
| `sso.provider_acr`                     | string or null               | `provider_acr`                     |
| `sso.provider_authn_context_class_ref` | string or null               | `provider_authn_context_class_ref` |
| `sso.link`                             | string or null               | `link_id`                          |
| `sso.link_provenance`                  | string or null               | `link_provenance`                  |
| `sso.provider_session_deadline`        | string (UTC instant) or null | `provider_session_deadline`        |
| `sso.session_not_after`                | string (UTC instant) or null | `session_not_after`                |
| `sso.enforcement_version`              | string or null               | `enforcement_version`              |

A session with no provenance from this package contributes nothing (`[]`): an absent key means "not established
through this package", and a `null` value means "established through it, without that fact". Every value is plain: a
string, a list of strings or `null`, never an object. Enums are their backed string values, and each instant is the
stored form's own string (`Provenance::INSTANT_FORMAT`, UTC, its microseconds exact), so a policy can read the keys
without depending on the package, a context that holds only plain values takes them as they are, and `of($provenance)`
and `fromStored($provenance->toArray())` answer identical arrays. `Provenance` keeps its times as UTC
`CarbonImmutable` instants for a caller in PHP; only the projection is plain. The key names are constants on
`AuthenticationContext` and are stable from 1.0.0.

## Success Path

- A linked `sign_in` is admitted inside the caller's transaction; `RedemptionResult::$provenance` holds the connection,
  tenant, protocol, provider time, accepted evidence, exact link and its provenance, both deadlines and the enforcement
  version. The adapter writes `toArray()` with the session in the same transaction.
- A later request reads the stored array and calls `AuthenticationContext::fromStored()` for the `sso.*` keys.
- A `sign_in` that activates a verified domain reservation captures the activated link as `verified_domain`. A later
  confirming `link` turns the link row to `link_purpose`, captures nothing, and leaves every session's stored
  `verified_domain` as it was; only a new sign-in captures `link_purpose`.

## Failure / Edge Cases

- A refused redemption, a `link`, a `reauthenticate` and the standalone `redeem()` of a `link` answer no provenance.
- An unlinked `sign_in` is captured with `link_id` and `link_provenance` `null`.
- A linker other than the package's store that does not state a link's provenance leaves `link_provenance` `null` while
  `link_id` is kept.
- A stored form from another version, or edited by hand, is an `UnexpectedValueException`, which the adapter treats as a
  server error rather than as a session with no provenance.
- Both raw context keys stated at once, or a link provenance with no link, is refused at construction and on restore.

## Implementation Anchors

- `src/Sessions/Provenance.php`, `src/Sessions/AuthenticationContext.php`, `src/Sessions/Enums/ContextKey.php`,
  `src/Sessions/Enums/ContextValueType.php`.
- `src/Handoffs/HandoffRedemption.php` (`redeemed()`), `src/Handoffs/RedemptionResult.php` (`$provenance`).
- `src/Handoffs/HandoffRecheck.php` (`admit()`), `src/Handoffs/Redemption/Judgement.php`, `Admission.php`,
  `RedemptionContext.php`, `SignInBranch.php`; `src/Contracts/PurposeBranch.php`.
- `src/Links/LinkResolution.php` (`$origin`), `src/Links/LinkStore.php`, `src/Linking/ReservationActivation.php`.

## Authoritative Tests

- `tests/Feature/Sessions/ProvenanceCaptureTest.php`: capture through the public flow, a confirming link and a
  re-authentication leaving the stored provenance as it was, both deadlines, the enforcement version, and the stored
  form through a database JSON column.
- `tests/Unit/Sessions/ProvenanceTest.php`: what `capture()` takes, from what, and when it takes nothing; only
  registered methods and a raw context class in its domain kept, neither failing a sign-in.
- `tests/Unit/Sessions/StoredProvenanceTest.php`: the stored form, its plain values, its restoration and refusals,
  each part's domain at its edge, the worst case within 4,096 bytes as JSON with every limit used, and redaction.
- `tests/Unit/Sessions/AuthenticationContextTest.php`: every key, its plain value, instants as stored, null versus
  absent, identical projections of a provenance and its stored form, and purity.
- `tests/Unit/Handoffs/JudgementTest.php`, `tests/Unit/Handoffs/AdmissionTest.php`,
  `tests/Unit/Links/LinkResolutionTest.php`, `tests/Unit/Handoffs/RedemptionResultTest.php`.

## Change Triggers

- A part added to the stored form, or a limit loosened: the worst case is worked out again and stays within
  `MAX_STORED_JSON_BYTES`.
- A key added to, or a meaning changed in, the stored form: a new version, with version 1 still read.
- A new source of any captured fact, which must remain the admitted redemption.
- A purpose that establishes a session.
- Anything the projection exposes about the person, which it must not.
