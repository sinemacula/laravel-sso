# OIDC Callback

## Purpose

This note records how the `oidc` driver reads a callback, correlates it, judges it against the request consumed for it,
and exchanges its code at the token endpoint (SSO-5.4, SSO-5.5, SSO-5.7, SSO-7.1, SSO-7.2, SSO-7.6, RFC 9207, RFC 9700
§4.4.2, RFC 7523). The driver as a whole is `oidc-driver.md`; the request's consumption and the completion's locks are
`completion.md` and `authorization-requests.md`; the ID token is `oidc-id-tokens.md`; UserInfo and the claims are
`oidc-claims.md`.

## Invariants

### Reading the raw query

- `Protocols\Oidc\CallbackParameters::parse()` reads `CompletionRequest::query()`, the raw query, and never a
  framework's parsed query, which would hide a repeat, make an array of `state[]` and fold names. It answers `null`, a
  refusal, when:
  - the query is empty, or longer than `OidcLimits::maxCallbackQueryBytes()` (raw bytes), or holds no parameter;
  - it holds more than `OidcLimits::maxCallbackParameters()` parameters;
  - a name repeats once decoded, compared exactly and case-sensitively (`st%61te` repeats `state`, `State` does not);
  - a name holds `[` or `]`, the shape of an array;
  - a decoded name or value is longer than `OidcLimits::maxCallbackParameterBytes()`;
  - a decoded name or value is not valid UTF-8 or holds a control character (C0, DEL or C1).
- It splits on `&`, ignores empty segments, splits each pair at its first `=` and form-decodes both sides. A name the
  callback does not read is ignored, yet counts towards the caps and may not repeat, and its value is not kept.
- `code()`, `state()`, `iss()` and `error()` are the only values kept, in a `\SensitiveParameterValue`. A dump and JSON
  encoding show the names of those present and no value; it refuses to be serialised or unserialised.

### Correlation

- `CallbackCorrelator::correlate()` is the driver's `correlate()`. It answers `Correlation::solicited($state)` only for
  a `GET` (`response_mode=query` alone) whose query is not refused and whose `state` is exactly 43 base64url characters,
  the package's 256-bit state. Anything else is `Correlation::uncorrelated()`, which the pipeline reports as
  `request_unknown` with no redirect target and nothing consumed (SSO-5.7). It logs nothing and reads no other value.
- The state is only ever looked up by its digest, by the consumption (`authorization-requests.md`), which refuses a
  request started through another connection with `connection_mismatch`, redirected to that request's application. So a
  response without `iss` is accepted only at the callback of the request's own connection: the mix-up defence of RFC
  9700 §4.4.2.
- A second callback of the same `state` finds the request consumed: `request_unknown`, and no token request.

### The callback, in order

`CallbackCompletion::complete()` is the driver's `complete()`, called by the `validation` step once the request is
consumed. Each refusal is a value, and the request stays consumed whatever happens:

1. The query is parsed again; a refusal now is `response_invalid`.
2. RFC 9207, before the response is handled as a success or an error: an `iss` present must equal
   `ConsumedRequest::$expectedIssuer` byte for byte, and one absent is accepted only when
   `ConsumedRequest::$issuerRequired` is false. Otherwise `issuer_mismatch`. An `iss` present on a request that recorded
   no issuer is refused too.
3. `error` and `code` both present, neither present, or an empty `code` is `response_invalid`. `error` alone is
   `provider_error`.
4. The token request (`TokenExchange`), with no credential `connection_unavailable`, and its answer
   (`TokenResponseReader`).
5. `IdTokenValidator::validate()`, whose refusal is the answer, then `ClaimsAssembler::assemble()`, whose `Completion`
   is the answer.

### The token request

- `TokenExchange::credentials()` builds the connection's one client authentication for the one attempt:
  - `client_secret_basic` and `client_secret_post`: `FetchCredentials` with the client id and
    `ConnectionSecrets::revealFor()`'s secret;
  - `private_key_jwt`: `KeyRing::current(KeyUse::CLIENT_ASSERTION)`, its private half from `KeyRing::privateKey()`, and
    `JoseAdapter::signClientAssertion()` with the client id, the token endpoint exactly and the clock's now, so every
    attempt has a fresh `jti`;
  - no secret, no current key or an unknown method: `null`, which the callback refuses with `connection_unavailable`.
- `TokenExchange::send()` sends `FetchRequest::token()` through the fetcher once, with exactly
  `grant_type=authorization_code`, `code`, `redirect_uri` (the endpoint resolver's callback, as the start sent it, never
  from the request, SSO-5.5) and `code_verifier`; `OidcLimits::tokenTimeoutSeconds()` and `maxTokenResponseBytes()` are
  the request's own. `FetchRequest` refuses a form that would add a second client authentication.
- It is one attempt: nothing here or in the fetcher retries a request carrying a credential. A timeout or a server error
  is refused and the request stays consumed, since the code may have been spent.
- The PKCE verifier is decrypted by `ConsumedRequest::codeVerifier()` inside `send()` alone, once the response has
  passed every check before the token request. A request that keeps none is a `LogicException`; a ciphertext no key
  decrypts propagates (SSO-11.4).
- `send()` refuses to run inside a transaction on the storage connection, as `CompletionService` does, so a provider
  call never holds a lock.

### The token response

`TokenResponseReader` reads the fetcher's result; nothing else of the body is read or kept:

| Answer                                                                  | Refusal                         |
|-------------------------------------------------------------------------|---------------------------------|
| refused or failed, a timeout and a body over the cap among them         | `fetch_refused`, `fetch_failed` |
| `400` or `401`, a JSON object with a non-empty string `error`           | `provider_error`                |
| any other non-`2xx`, `3xx` and `5xx` among them                         | `fetch_failed`                  |
| `2xx`, not a JSON object by `StrictJson` (a repeated member among them) | `token_response_invalid`        |
| `2xx`, `id_token` missing, empty or not a string                        | `id_token_invalid`              |
| `2xx`, `access_token` not an RFC 6750 b64token                          | `token_response_invalid`        |
| `2xx`, `token_type` not `bearer` in any case                            | `token_response_invalid`        |

`tokens()` builds the `Tokens\TokenResponse` of an answer not refused. A `refresh_token` and every other member are
ignored and never retained.

### What is logged

- Only `CallbackCompletion` logs, through the sanitising logger: `sso.oidc.callback_error` for an `error` in the
  authorisation response and `sso.oidc.token_error` for one from the token endpoint, each at `notice`, with
  `connection_id`, `request_reference` and `error`.
- `error` is logged only when it has the shape of a code (`[A-Za-z0-9_.:-]{1,64}`), otherwise as `[unrecognized]`, so
  prose a provider puts there reaches no log. `error_description` and `error_uri` are never read, so they reach no log,
  event or result (SSO-5.7). The response body, the tokens, the code, the state, the verifier and the client assertion
  are never logged or evented (SSO-7.6).

### Transactions and trust

- The callback runs outside any transaction (`CompletionService`), so the token request holds no lock and `correlate()`
  and `complete()` never break the global lock order.
- The consumption refuses a request whose trust version is not the connection's before any provider is called. A trust
  change while the token request is in flight (the client secret, `jwks_uri`, anything `OidcSetting::freshness()` calls
  trust) voids the request and raises the trust version under the connection's lock, so the completion's locked step
  refuses it with `connection_unavailable`, with no handoff.

### Statelessness

Every class here holds its collaborators only, and reads the limits on each call (SSO-11.2).

## Success Path

1. The browser arrives at the connection's callback; the application's controller hands
   `CompletionRequest::fromRequest()` to `CompletionService::callback()`.
2. `correlate()` reads the `state` from the raw query; the pipeline consumes its request.
3. `complete()` checks `iss`, finds exactly a code, and sends the one token request.
4. The token response is read, the ID token validated and the claims assembled.
5. Under the locks, the link is resolved, enforcement judged and the handoff code issued:
   `[ResultVerified, HandoffIssued]`.

## Failure / Edge Cases

- A refused query, a malformed `state` or a replay: `request_unknown`, `[FlowFailed]` with no `request_reference`, no
  redirect target, nothing consumed by this callback.
- Refused once the request is consumed: `[FlowFailed]` with the `request_reference`, redirected to the request's
  application with the code.
- The same callback twice at once: the request's row lock lets one consume it and send the one token request; the other
  is `request_unknown`.
- A verified response whose connection changed meanwhile: `[ResultVerified, FlowFailed]` with `connection_unavailable`.
- A database error, an undecryptable verifier or secret, and a misconfigured limit propagate as server errors with the
  request consumed (SSO-11.4), never as a failure redirect.
- A token request to an address the fetcher refuses: `fetch_refused`.

## Implementation Anchors

- `src/Protocols/Oidc/CallbackParameters.php`, `CallbackCorrelator.php`, `CallbackCompletion.php`.
- `src/Protocols/Oidc/TokenExchange.php`, `TokenResponseReader.php`, `Tokens/TokenResponse.php`.
- `src/Fetching/FetchRequest.php`, `FetchCredentials.php`, `src/Connections/ConnectionSecrets.php`,
  `src/Keys/KeyRing.php`, `src/Protocols/Oidc/Jose/JoseAdapter.php`.
- `src/Testing/FakeOpenIdProvider.php`, `src/Testing/Oidc/FakeTokenEndpoint.php`, `FakeAuthorization.php`.

## Authoritative Tests

- `tests/Unit/Protocols/Oidc/CallbackParametersTest.php`: splitting, decoding, every refusal and each cap at, under and
  over; no value in a dump.
- `tests/Feature/Protocols/Oidc/CallbackCorrelatorTest.php`: `GET` only, the raw query alone, the shape of `state`.
- `tests/Feature/Protocols/Oidc/CallbackCompletionTest.php`: `iss` first, `error` and `code`, what is logged, no
  credential, the verifier decrypted lazily, the doubles' hand-over.
- `tests/Feature/Protocols/Oidc/TokenExchangeTest.php`: each client authentication, the assertion's claims, the exact
  form, one attempt, no transaction, every answer's exact reason.
- `tests/Feature/Completion/OidcCallbackTest.php`: all of it through `CompletionService::callback()` with the fake
  provider's strict endpoint: the mix-up defence, event sequences, and the scan for provider values in events, logs and
  dumps.
- `tests/Integration/Completion/ConcurrentOidcCallbackTest.php`: the same callback twice at once, and a trust change
  with the token request in flight, plainly and inside an administrator's own transaction.
- `tests/Performance/OidcCallbackQueryBudgetTest.php`: exact query budgets.

## Change Triggers

- A change to what the query may hold, or to its caps.
- A change to the order of the checks, or to what `iss` must equal.
- A new client authentication, or a change to the token request's form, timeout, cap or attempts.
- A change to what is read of a token response, or to its mapping to failure reasons.
- A change to what is logged of a provider's error.
