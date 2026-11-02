# OIDC ID Tokens

## Purpose

This note records how the `oidc` driver judges an ID token (SSO-7.3, SSO-7.4, SSO-5.10, OpenID Connect Core 1.0
§3.1.3.7): every check, the order they run in, and the reason each answers with. The driver as a whole is
`oidc-driver.md`; the callback and the token request that bring the token are `oidc-callback.md`; the JOSE adapter is
`jose-adapter.md`, and why the library decides none of this `jose-library.md`; the JWKS and their refetch are
`oidc-discovery.md`; what is built from a validated token is `oidc-claims.md`.

## Invariants

- `Protocols\Oidc\IdTokenValidator::validate()` runs the checks below in this fixed order, and the first failure
  answers: a token failing two checks always reports the earlier. Every check is always on, whatever a connection's
  settings say. A refusal is a value, `IdTokenValidation::refused($reason)`; only a misconfiguration or a database error
  propagates (SSO-11.4).

  | Step | Check                                                                                            | Reason                                                            |
  |------|--------------------------------------------------------------------------------------------------|-------------------------------------------------------------------|
  | 1    | `Jose\CompactToken::parse()` reads it, within `OidcLimits::maxIdTokenBytes()`                    | `id_token_invalid`                                                |
  | 2    | `Metadata\ProviderKeys::select()` finds its key among the connection's stored JWKS               | `signature_invalid`, `connection_unavailable` once overtaken      |
  | 3    | `Jose\JoseAdapter::verify()` verifies its signature with that key, under the allow-list          | `signature_invalid`                                               |
  | 4    | `IdTokens\ClaimTypes`: every claim the package reads has its exact type                          | `id_token_invalid`                                                |
  | 5    | `iss` is exactly `OidcOptions::issuer()` and exactly the issuer the request pinned               | `issuer_mismatch`                                                 |
  | 6    | `IdTokens\AudienceRules`: `aud` and `azp`                                                        | `audience_mismatch`                                               |
  | 7    | `Jose\TimeClaims::check()`: `exp`, `iat` and `nbf`                                               | `assertion_expired`                                               |
  | 8    | `nonce` is a string of 1 to 512 bytes whose digest the request stored, compared in constant time | `nonce_mismatch`                                                  |
  | 9    | `IdTokens\AuthenticationTimeRules`: `auth_time`                                                  | `assertion_expired`, `id_token_invalid`, `authentication_expired` |
  | 10   | `IdTokens\AccessTokenHash`: `at_hash`, when present                                              | `at_hash_mismatch`                                                |

- A claim decides a refusal only once the signature has verified with a key the connection holds. A token that is not
  the provider's therefore learns nothing from which reason it gets.
- Before an unknown-`kid` refetch, and only then, steps 4 to 10 run on the token's unverified claims, for rejection
  alone: a token that would be refused anyway (another issuer, audience or nonce, out of its time window, a claim of the
  wrong type) fetches nothing and leaves the shared cooldown unclaimed, so it cannot spend the window a good token
  needs. It is answered `signature_invalid`, as any token no held key verifies is. Unverified claims never establish
  identity or choose a URL to fetch, and every step runs again after the signature.
- The validator reads the clock once per call and the skew (`Clock\ClockSkew`) and the limits (`OidcLimits`) on each
  call. It keeps nothing between calls (SSO-11.2), and its collaborators keep nothing either. It runs outside any
  transaction, since step 2 may fetch; only the refetch's own claim and write touch a row.
- It logs nothing: `ProviderKeys` logs how a refetch ended. Nothing it throws holds the token, and every array of claims
  it passes along is `#[\SensitiveParameter]` (SSO-7.6, SSO-11.9). `TokenResponse`, `CompactToken` and
  `ValidatedIdToken` keep the tokens, headers and claims in `\SensitiveParameterValue`, so a dump, a stack trace or a
  log record cannot show them.

### Algorithm and key (steps 1 to 3)

- `CompactToken::parse()` refuses anything but a compact JWS of three canonical base64url segments: a JWE, `crit`,
  `b64`, `enc`, `zip`, a repeated JSON member at any depth, a `kid` that is not a non-empty string. `jku`, `x5u`, `jwk`
  and `x5c` are never read: a key comes only from the JWKS stored with the connection.
- The allow-list is the connection's `id_token_algorithms`, read through `OidcOptions::algorithms()`, and never holds
  `none` or an HMAC: `AlgorithmAllowList::of()` refuses them, and `JoseAdapter` registers only the asymmetric
  algorithms.
- `ProviderKeys::select()` answers found, unknown or refused. Only found goes on. Unknown (no stored key has the token's
  `kid`, or no `kid` and no key fits, after the single refetch inside it) and refused (an algorithm off the list, a key
  of another type or curve, a `kid` absent among two keys that fit) are both `signature_invalid`, so a refusal does not
  say which keys the connection holds. A connection gone, or a trust change found by a failed claim of the cooldown or a
  lost compare and set, is `overtaken`, which is `connection_unavailable`.
- The JWKS refetch is the consumer side of `oidc-discovery.md`: a token that names an unknown `kid` claims the cooldown
  before anything is fetched, so unknown `kid`s within the cooldown fetch nothing. An unknown supplied `kid` never falls
  back to a key without one. A refused token never fetches.

### Claim types (step 4)

- Required, each with its type: `iss` a string; `sub` a string of 1 to 1024 bytes, kept exactly, never trimmed or
  normalised; `aud` a non-empty string, or a non-empty JSON array of non-empty strings with no two the same; `exp` and
  `iat` JSON numbers.
- When present, a `null` being present: `nbf` and `auth_time` JSON numbers; `azp`, `nonce`, `at_hash` and `email`
  strings; `acr` and `sid` strings of 1 to 1024 bytes; `amr` a JSON array of at most 32 strings of 1 to 255 bytes.
  Nothing else is judged: an `email_verified` that is not a JSON boolean refuses nothing and gives no evidence
  (`oidc-claims.md`).
- A JSON object is never read as a list. `Jose\StrictJson::decodeObject()` decodes objects to PHP arrays, so
  `{"0":"client"}` and `["client"]` are the same array by then; `ClaimTypes::refusal()` reads the verified payload again
  as JSON wrote it (`decodeAsWritten()`) to tell them apart for `aud` and `amr`.
- A number too large for a float reads as infinity and is refused, or it could never expire. An integer too large for
  PHP's is kept as its digits by `decodeObject()`, so a numeric date, which must be a number, refuses it rather than
  reading a finite float.
- A number is never read as a string of its digits. That same reading would make
  `{"sub":123456789012345678901234567890}` a string, so `ClaimTypes::refusal()` requires `iss`, `sub`, `aud`, `azp`,
  `nonce`, `at_hash`, `email`, `acr`, `sid` and `amr` to be strings, or lists of them, in the `decodeAsWritten()`
  reading, where such a number is a float. A token that passes hands on its claims in that reading too
  (`CompactToken::members()`), so a claim mapped to an attribute is never a number's digits either.

### Issuer and audience (steps 5 and 6)

- `iss` is compared byte for byte with both the connection's issuer and the issuer the request pinned when it started,
  so a token never passes against an issuer its flow was not started for.
- `AudienceRules` compares exactly, with no case folding or trimming: `aud` holds the client id; every other audience is
  in `trusted_audiences` (none by default); with more than one audience `azp` is required; `azp`, when present, is the
  client id. An audience the connection trusts is never enough on its own.

### Times (steps 7 and 9)

- Every time is the package's own check against `Contracts\Clock`, compared at full precision
  (`TimeClaims::numericDate()` and `instant()`). The library's time checks never run. With skew `s`, at `now`:

  | Claim       | Refused when                                                  | Reason                   |
  |-------------|---------------------------------------------------------------|--------------------------|
  | `exp`       | `now >= exp + s`                                              | `assertion_expired`      |
  | `iat`       | `iat > now + s`, or `now - iat > max age + s`                 | `assertion_expired`      |
  | `nbf`       | `nbf > now + s`                                               | `assertion_expired`      |
  | `auth_time` | `auth_time > now + s`                                         | `assertion_expired`      |
  | `auth_time` | absent when `max_age` or a `reauthenticate` asked             | `id_token_invalid`       |
  | `auth_time` | a positive `max_age`, `now - auth_time > max_age + s`         | `authentication_expired` |
  | `auth_time` | `max_age` 0 or `reauthenticate`, `auth_time < started at - s` | `authentication_expired` |

- `auth_time` is never inferred from `iat`: a token that has only `iat` has no authentication time.
- Reauthentication is judged relative to the request, never the callback. A `reauthenticate` sends `max_age=0` upstream
  whatever the connection's is (`oidc-requests.md`), and a connection's own `max_age` of 0 sends the same. Locally that
  means an authentication made for this request: `auth_time` not before the request started less the skew, and not past
  now plus the skew, however long the person then took to come back and however slowly the callback is processed. A
  `max_age` of 0 is never a callback-age check.
- A connection's positive `max_age` is the configured authentication age, measured from now, and applies to a
  `reauthenticate` too. A connection with none leaves an old `auth_time` alone. The maximum age of `iat` is
  `sso.oidc.id_token_max_age_seconds`.
- A request's start is kept to the whole second, so `auth_time` is compared with the start as stored.

### Nonce and `at_hash` (steps 8 and 10)

- The request keeps only the nonce's digest, so `ConsumedRequest::isNonce()` hashes the claim and compares in constant
  time. A request that stored none admits no token. A token with no `nonce` is `nonce_mismatch`; one of the wrong type
  stopped at step 4.
- `at_hash` must be the unpadded base64url of the left half of the access token's hash, by the hash of the token's
  algorithm size (SHA-256, SHA-384 or SHA-512 for `*256`, `*384` and `*512`), compared with `hash_equals()`. An absent
  one is accepted, as the code flow allows.

### Trust changes

- The validator judges the token against the settings the completion read and the keys stored at that moment. It does
  not decide whether the connection is still trusted: the completion does, under its locks (`completion.md`), where a
  request voided or of another trust version is `connection_unavailable`.
- A key added by the refetch changes no trust, so a rotation that adds a key verifies its own callback. A key removed or
  replaced voids what is in flight, but spares the callback that asked, whose token verified under the keys the rotation
  left: that one sign-in may finish across exactly that transition (`oidc-driver.md`). Every other flow and every issued
  handoff stays voided, since the removal may be the response to a compromise, and any independent change before the
  final locks refuses the sign-in.
- A trust change while the token or UserInfo request is in flight refuses the completion `connection_unavailable`. A
  trust change while the refetch's own JWKS request is in flight makes that refetch lose its compare and set: it writes
  nothing and reports `metadata_conflict`, so the fetched key is never used, and `Metadata\ProviderKeys` answers
  `overtaken` when no stored key is the token's, as it does when a failed claim of the cooldown finds the connection
  gone or its trust version raised, which is `connection_unavailable` too, before the locks. A refetch that lost to a
  change that is not one of trust stays `signature_invalid`. The request is voided and no handoff is issued whichever
  answers.

## Success Path

1. The token endpoint's answer is read into a `TokenResponse` (`oidc-callback.md`).
2. Steps 1 to 3 find the key and verify the signature.
3. Steps 4 to 10 judge the claims.
4. `IdTokenValidation::validated()` holds a `ValidatedIdToken` of its `iss`, its `sub` and its claims, which
   `ClaimsAssembler` reads and nothing keeps.

## Failure / Edge Cases

- An unknown `kid` whose refetch failed or is cooling down: `signature_invalid`, reported after `JwksRefreshFailed` for
  a refetch that failed, and alone within the cooldown.
- An unknown `kid` on a token already disqualified by its claims: `signature_invalid`, with nothing fetched and the
  cooldown unclaimed.
- A slow callback, the person authenticating for this request and taking minutes to come back: it passes, whatever its
  `max_age` of 0 says, as long as the token's own `exp` and `iat` do.
- A token over the cap: `id_token_invalid`, before anything else of it is read.
- A `sub` that fits the token but not the result cannot happen: step 4 holds it to `VerifiedResult::MAX_SUBJECT_LENGTH`.
- An `auth_time` the result cannot store (negative, or past the year 9999): `ClaimsAssembler` refuses it
  `id_token_invalid` once this validation has passed (`oidc-claims.md`).
- `email_verified` as the string `"true"`, which some providers send: the token passes and the flag gives no evidence
  (`oidc-claims.md`).
- A misconfigured allow-list or limit, and a database error, propagate as server errors.

## Implementation Anchors

- `src/Protocols/Oidc/IdTokenValidator.php`.
- `src/Protocols/Oidc/IdTokens/ClaimTypes.php`, `AudienceRules.php`, `AuthenticationTimeRules.php`,
  `AccessTokenHash.php`.
- `src/Protocols/Oidc/Tokens/IdTokenValidation.php`, `ValidatedIdToken.php`, `TokenResponse.php`.
- `src/Protocols/Oidc/Jose/CompactToken.php`, `JoseAdapter.php`, `TimeClaims.php`, `AlgorithmAllowList.php`.
- `src/Metadata/ProviderKeys.php`, `JwksRefetcher.php`, `src/Protocols/ConsumedRequest.php`, `src/Clock/ClockSkew.php`.
- `src/Testing/Oidc/HostileIdTokens.php`, `FakeIdToken.php`.

## Authoritative Tests

- `tests/Unit/Protocols/Oidc/IdTokens/`: each helper, each type confusion, each boundary at, under and over, the
  audience bypasses and `at_hash` for each hash size.
- `tests/Feature/Protocols/Oidc/IdTokenValidatorTest.php`: each reason, the order pinned by tokens failing two checks,
  the limits and the skew read per call, the refetch, the missing-`kid` rule, the nonce's cap, a dump showing nothing.
- `tests/Feature/Completion/OidcAdversarialCallbackTest.php`: every hostile token through the public callback path, its
  JWKS fetches counted, wrong claims from the token endpoint, the honest control, and key rotation end to end.
- `tests/Feature/Completion/OidcCompletionEventSequenceTest.php`: whole event sequences and contexts.
- `tests/Integration/Logging/NoProviderTokensLeakTest.php`: events, logs, results, stored rows and dumps hold no
  provider token, and the reference is the only flow identifier (SSO-7.6, SSO-11.9).
- `tests/Integration/Completion/OidcTrustChangeRaceTest.php`: a completion whose token, JWKS or UserInfo request is in
  flight while the connection is disabled, its issuer migrated or its secret rotated.
- `tests/Integration/Completion/OidcWorkerIsolationTest.php`: consecutive callbacks for different tenants (SSO-11.2).

## Change Triggers

- A new check, a change to the order, or a change to the reason a check answers.
- A new claim the package reads, or a change to its type or caps.
- A change to how a key is chosen or a refetch is reached.
- A change to what the validator holds, or to where a trust change is judged.
