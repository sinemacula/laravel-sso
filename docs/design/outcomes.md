# Outcomes and Throttling

## Purpose

This note records how the package's contracts and helpers answer: which outcomes are values, what `null` and `bool`
may mean, what shape a result takes, how throttling is answered, and what an exception means. It is the convention of
`laravel-authentication`'s outcomes, kept so the suite reads as one codebase; each operation keeps its own type, and
the convention is the shape.

## Invariants

- **Expected refusals are values.** A refusal of untrusted input (a response, a callback, a code, a verifier) or of
  policy (a disabled connection, an application that does not allow external sign-in, throttling) is returned, never
  thrown. Exceptions mean a misconfiguration, an invalid argument from application code (`InvalidArgumentException`,
  `LogicException`) or a server error (a database error, a store that cannot answer), which propagates (SSO-11.4).
- **A result object when success carries a payload or the operation can be throttled.** It is `final readonly`, built
  only through named constructors (one per outcome), says which outcome it is through `is…()` predicates, carries its
  payload in nullable public properties set only for the outcome that has it, names a refusal by `reason`
  (`Events\Enums\FailureReason`), and carries `retryAfter` when it can be throttled. A result with more than two
  outcomes exposes `status`, a string-backed enum naming every outcome, success included.
- **An outcome enum when success carries nothing and nothing throttles.** It is string-backed and names its success
  case, so matching on the enum tells success from refusal.
- **`null` only for "nothing to act on"**, never for success or refusal; `bool` and `int` only for what an idempotent
  call changed. No union of a success type with a failure type.
- **Throttling is an outcome**: `rate_limited`, with `retryAfter`.
- **A value that carries a secret** (a credential, a token request's form, a response body) keeps it private, masks it
  in a dump and refuses to be serialised or unserialised, so it cannot reach a log, an exception, a queue or an event.

## Success Path

- `Contracts\Clock::now()` answers a `CarbonImmutable`.
- `Contracts\SingleUseStore::record()` answers `SingleUse\Enums\SingleUseOutcome`: `recorded` (success, the only answer
  that lets a flow proceed) or `seen`. A store that cannot tell throws.
- `Contracts\Fetcher::fetch()` takes a `Fetching\FetchRequest` (built per purpose, with the one credential that purpose
  may carry, `Fetching\FetchCredentials`) and answers a `Fetching\FetchResult`: `fetched` with the HTTP status code,
  headers and body (`isSuccessful()` for a `2xx`), `refused` (`fetch_refused`) or `failed` (`fetch_failed`), status
  `Fetching\Enums\FetchStatus`.
- `Contracts\AttemptLimiter::attempt()` takes a `RateLimiting\AttemptSubject` (built per flow) and answers a
  `RateLimiting\AttemptResult`: allowed, or `rate_limited` with `retryAfter` of at least one second.
- `Contracts\SecretEncrypter` answers strings; a ciphertext that cannot be decrypted is a server error, thrown.

### Management helpers (SSO-2.11, SSO-2.12)

The helpers that change connections, keys and certificates follow one shape, so an administration screen handles them
the same way:

- Every helper is scoped to a tenant: it takes the tenant's opaque id and the connection's id, and a connection of
  another tenant is answered exactly as an unknown one, `connection_not_found`.
- A change answers a result object (`final readonly`, named constructors, `is…()` predicates) carrying, on success, the
  summary of what it changed (a connection's summary, or a key's `Keys\KeySummary`), and on refusal a `reason` from the
  administration group of `FailureReason`: `freshness_required` (the freshness contract answered `stale`),
  `connection_not_found`, `key_not_found`, `settings_invalid` (with `violations`, a list of
  `Connections\SettingViolation`, each naming a setting and a `Connections\Enums\ViolationCode`, never a value),
  `protocol_unavailable` and `key_state_conflict`.
- A change that changed nothing (enabling an enabled connection, an update that gives the stored values) succeeds and
  says so, writes nothing and reports nothing.
- The order is fixed: find the connection (and the key) on the write connection; validate what was given; ask the
  freshness contract with each operation the change is (`Freshness\FreshnessGate`); then write, in one transaction on
  the storage connection, and report through `Administration\AdministrationEvents` inside it. A refusal at any step
  writes nothing and dispatches nothing.
- A read answers `null` for a connection it did not find (`get()`), and a list, possibly empty, otherwise.
- The domain helpers (`Domains\DomainService`) answer a `Domains\DomainResult` the same way, with the domain
  reasons of `FailureReason` (`domain_not_found`, `domain_unavailable`, `domain_claim_expired`,
  `domain_record_not_found`, `domain_lookup_failed`), and `rate_limited` with `retryAfter` for a verification; see
  `domains.md`. The enforcement helpers add `feature_disabled` and `completed_sign_in_required`; see
  `enforcement.md`.
- An application's mistake (an empty tenant id, an acting identity with no type) is an `InvalidArgumentException`; a
  database error, a `SecretEncrypter` that cannot encrypt or a key OpenSSL cannot generate propagates.

## Failure / Edge Cases

- A failure reason is a stable code (`FailureReason`), never prose; the application words it (SSO-12.6). A failure
  redirect, a failure event and a refused result carry the same code.
- A fetch's detail (the host that did not resolve, the TLS error) goes to the logs only; the result carries the code.
- A database error is never turned into a refusal: it propagates, and the application answers it as a server error.

## Implementation Anchors

- `src/Events/Enums/FailureReason.php`; `src/SingleUse/Enums/SingleUseOutcome.php`.
- `src/Fetching/FetchRequest.php`, `src/Fetching/FetchCredentials.php`, `src/Fetching/FetchResult.php`,
  `src/Fetching/Enums/`.
- `src/RateLimiting/AttemptSubject.php`, `src/RateLimiting/AttemptResult.php`, `src/RateLimiting/Enums/`.
- `src/Contracts/`.
- `src/Connections/SettingViolation.php`, `src/Connections/Enums/ViolationCode.php`, `src/Freshness/FreshnessGate.php`,
  `src/Administration/AdministrationEvents.php`; the management helpers in `src/Connections/` and `src/Keys/`.

## Authoritative Tests

- `tests/Unit/Events/Enums/FailureReasonTest.php`, `tests/Unit/SingleUse/SingleUseOutcomeTest.php`.
- `tests/Unit/Fetching/FetchRequestTest.php`, `tests/Unit/Fetching/FetchCredentialsTest.php`,
  `tests/Unit/Fetching/FetchResultTest.php`.
- `tests/Unit/RateLimiting/AttemptSubjectTest.php`, `tests/Unit/RateLimiting/AttemptResultTest.php`.

## Change Triggers

- A new public operation, or a change to what one returns.
- A new outcome of an existing operation, a new failure reason, or a refusal that becomes or stops being an exception.
