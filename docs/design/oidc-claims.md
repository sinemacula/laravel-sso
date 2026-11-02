# OIDC Claims

## Purpose

This note records how the `oidc` driver builds what a completion verified (SSO-2.9, SSO-2.10, SSO-7.5, SSO-7.6, SSO-7.7,
SSO-8.1, SSO-8.8): the UserInfo request and how its answer is judged, where each claim of the result comes from, how an
email and its `email_verified` are paired, and why no provider token outlives the completion. The driver as a whole is
`oidc-driver.md`; the callback and the token request are `oidc-callback.md`; the ID token is `oidc-id-tokens.md`; how
the verified result is built from the claims is `completion.md`.

## Invariants

### UserInfo

- `Protocols\Oidc\ClaimsAssembler::assemble()` is called with an ID token every check passed, outside any transaction.
  Only a connection with `fetch_userinfo` on makes the request, and `OidcSettings` then requires `userinfo_endpoint`, so
  a connection that fetches but names none is the caller's mistake (`LogicException`).
- While on, UserInfo is mandatory: every refusal below refuses the completion, the request stays consumed and no code is
  issued, with no fallback to the ID token alone. It is read before anything else is judged.
- `UserInfoReader::fetch()` sends one attempt, with no retry by code or middleware, through the fetcher (SSO-2.9):
  `GET`, the access token as its only credential (`FetchRequest::userInfo()`, `FetchCredentials::accessToken()`), held
  to `OidcLimits::userInfoTimeoutSeconds()` and `maxUserInfoBytes()`. Inside a transaction on the storage connection it
  is a `LogicException`, so a provider call never holds a lock.
- `UserInfoReader::refusal()` judges the answer, in this order:

  | Answer                                                                     | Refused with       |
  |----------------------------------------------------------------------------|--------------------|
  | The request refused before it was sent                                     | `fetch_refused`    |
  | The request failed: a timeout, or a body over the cap                      | `fetch_failed`     |
  | `401`, `403`                                                               | `provider_error`   |
  | Any other status outside `2xx`                                             | `fetch_failed`     |
  | `2xx` with the content type `application/jwt`, in any case                 | `userinfo_invalid` |
  | A body `Jose\StrictJson` does not read as an object: a repeated member too | `userinfo_invalid` |
  | `sub` missing, not a string, or not equal to the ID token's byte for byte  | `userinfo_invalid` |
  | A claim the package reads of the wrong type                                | `userinfo_invalid` |

- A signed or encrypted UserInfo response is not supported, so it is refused whatever its body. Any other content type
  is not judged: the body decides.
- The claims the package types are `email` (a string of 1 to 320 bytes) and `name`, `given_name` and `family_name`
  (strings). A member present as `null` is not missing, so it is refused; a member absent is unknown. `email_verified`
  never refuses anything (below), and no other claim is judged here, since the mapping keeps only strings and lists of
  strings.
- The reader reads the body with `StrictJson::decodeMembers()`, where an integer too large for PHP is a float, so
  `{"sub":123456789012345678901234567890}` is not a string and a number is never taken for its digits, in the claims it
  judges and in those it hands on.

### Where the claims come from

- From the ID token alone, whatever UserInfo says: the issuer (`ValidatedIdToken::$issuer`), the subject exactly as
  received, `auth_time`, `amr`, `acr` and `sid`. UserInfo's own `iss`, `auth_time`, `acr`, `amr` or `sid` is ignored.
- `authenticatedAt` is `auth_time` at full precision, in UTC, or none when absent, and `iat` never stands in for it.
  `methods` is `amr` or none, `contextClass` is `acr`, `providerSessionId` is `sid`. `providerSessionDeadline` is always
  `null`, since OIDC states none. `nameIdFormat` is `null`.
- A claim that does not fit what a result holds is `id_token_invalid`, never an exception, though the ID token's
  validation types them first: `amr` not a list of at most 32 strings of 1 to 255 bytes; `acr` or `sid` not a string of
  1 to 1024 bytes; `auth_time` not a number from `0` up to the last second of the year 9999, the most `StoredValues` can
  write and read back; an `email` that `EmailPairing::fits()` refuses; an issuer or subject over 1024
  bytes. A member present as `null` does not fit.
- The raw attributes the mapping reads are the ID token's claims with UserInfo's laid over them, so UserInfo wins for
  mapped attributes, less every name in `AttributeMapping::RESERVED_OIDC_SOURCES` from either source: the protocol and
  identity claims, `email_verified`, and any token or code a provider put among its claims. Their `email` is the pair's
  and is removed when there is no pair, so under a mapping that reads `email` the mapped email and the asserted pair
  never disagree. Names are kept as they are, a member named by digits included (`array_replace()`, never a spread).

### Email pairing

- `EmailPairing::of()` takes the pair from the ID token when it carries `email`, even when UserInfo has its own;
  otherwise from UserInfo when it was fetched and carries `email`; otherwise there is none.
- `email_verified` is read from that source alone, so another source's flag never vouches for an email: an ID token with
  an `email` and no flag is `null`, whatever UserInfo says. The owner decided how it reads: only JSON `true` is evidence
  of verification, JSON `false` stays `false`, and anything else (a string such as `"true"`, a number, an object, an
  array or `null`) gives no evidence and does not refuse the sign-in. Nothing is coerced. It is carried as `true`,
  `false` or `null` (unknown) in `Results\AssertedEmail` with its source (SSO-7.7), which the verified result keeps
  apart from the mapped attributes and stores with the handoff (`completion.md`).
- `EmailPairing::linkingEmail()` gives a `Results\LinkingEmail` only when the pair's `email_verified` is exactly `true`
  and the email has one `@` between a local part and a domain, by `LinkingEmail`'s own rule, with the pair's source and
  no organisation. Nothing is ever read from the mapped attributes (SSO-8.8). Whether a link is then made is P6's.

### Provider tokens are never kept

- The access token is read from `TokenResponse` for the UserInfo request and for nothing else here, and goes only into a
  `FetchCredentials`, which refuses to be serialised and shows it in no dump. The ID token is not read here at all. A
  refresh token is never kept by `TokenResponseReader`.
- `ClaimsAssembler` alone logs (`UserInfoReader` and `EmailPairing` never do), and only a `provider_error`:
  `sso.oidc.userinfo_error`, a notice, with `connection_id`, `request_reference` and `error`. The `error` is the code
  of the answer's `WWW-Authenticate` when it is one of RFC 6750 §3.1's (`invalid_request`, `invalid_token`,
  `insufficient_scope`) and `[unrecognized]` otherwise, so a provider that puts prose or a token in `error` reaches no
  log. A body, an `error_description` and the other parameters of the challenge are never read into a log, event or
  result (SSO-5.7).
- `VerifiedClaims` lives only for its completion: it refuses to be serialised, and its JSON and `AssertedEmail`'s show
  no email. The verified result holds no token. Its stored form holds the mapped attributes, the linking email and the
  asserted email, so the handoff store encrypts it; its JSON is the stored form but for the asserted email, shown as its
  source and flag.
- It answers `Completion::verified()` with no `ReplayRecord`: the single use of the request and of the code stand in for
  recording a replay. It reports no event: the pipeline reports `ResultVerified`, `HandoffIssued` or `FlowFailed`.
- It holds only `UserInfoReader` and the logger, and nothing of one completion for the next (SSO-11.2).

## Success Path

1. The callback's code is exchanged and the ID token validated (`oidc-callback.md`, `oidc-id-tokens.md`).
2. A connection that fetches UserInfo makes its one request; the answer's status, content type, `sub` and claims pass.
3. The ID token's claims are checked to fit; the email is paired; the attributes and the authentication context are
   built; a pair verified exactly gives the linking email.
4. The driver answers `Completion::verified($claims)`, and the pipeline builds the verified result (`completion.md`).

## Failure / Edge Cases

- UserInfo unreachable, timing out or over its cap: the completion fails with `fetch_failed` or `fetch_refused` and the
  request stays consumed, so the person starts again. With `fetch_userinfo` off, nothing is requested.
- An expired or under-scoped access token: `provider_error`, logged by its code alone.
- A `sub` that differs in case, in whitespace or in Unicode form from the ID token's: `userinfo_invalid`.
- `email_verified` as the string `"true"` or `"false"`, which some providers send: the sign-in goes on and the pair is
  unknown, from the ID token and from UserInfo alike. No provider's strings are read as booleans, so no linking email
  comes of one.
- A UserInfo member present as `null` for a claim the package reads: `userinfo_invalid`.
- A verified email that is not well formed: the asserted pair keeps it as it is, and there is no linking email.
- A connection whose mapping reads the email from another claim: the mapped email is that claim's, and the asserted pair
  is still the provider's `email`. `emailDomainVerified` judges the mapped one (`completion.md`).
- A database error or a misconfigured limit propagates (SSO-11.4). A token the token response's reader would have
  refused reaching `FetchCredentials::accessToken()` is the caller's mistake (`InvalidArgumentException`).

## Implementation Anchors

- `src/Protocols/Oidc/ClaimsAssembler.php`, `UserInfoReader.php`, `EmailPairing.php`.
- `src/Results/AssertedEmail.php`, `VerifiedClaims.php`, `VerifiedResult.php`, `LinkingEmail.php`.
- `src/Completion/ResultBuilder.php`, `src/Connections/AttributeMapping.php`.
- `src/Fetching/FetchRequest.php`, `FetchCredentials.php`, `src/Protocols/Oidc/OidcLimits.php`.

## Authoritative Tests

- `tests/Feature/Protocols/Oidc/UserInfoReaderTest.php`: the request pinned, every status, the content types, the cap
  at, under and over, a timeout, the malformed bodies, `sub` equality, the types of the claims read, the error code.
- `tests/Unit/Protocols/Oidc/EmailPairingTest.php`: every combination of the sources, and the linking email.
- `tests/Feature/Protocols/Oidc/ClaimsAssemblerTest.php`: UserInfo off and on, each refusal's exact reason, the whole
  claims pinned, UserInfo unable to change an identity or authentication claim, the mapping, the bounds of what fits.
- `tests/Feature/Protocols/Oidc/ClaimsTokensNeverKeptTest.php`: logs, dumps and serialised results, verified and
  refused, for the tokens, the body, the description and the email in JSON.
- `tests/Unit/Results/AssertedEmailTest.php`, `VerifiedResultTest.php`,
  `tests/Feature/Completion/ResultBuilderTest.php`: the pair stored, read back through the handoff store and redacted.

## Change Triggers

- A new claim the package reads, from either source, or a change to its type.
- A change to which source an email or an authentication claim comes from.
- UserInfo becoming optional when on, or a signed UserInfo response being supported.
- A decision to read anything but a JSON boolean as evidence in `email_verified`.
- The organisation claim (P6) reaching the linking email.
- Anything new logged, evented or kept from a provider's answer.
