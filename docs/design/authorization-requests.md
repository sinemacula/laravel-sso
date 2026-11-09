# Authorisation Requests

## Purpose

This note records how a flow starts and how its authorisation request is consumed (SSO-5.1, SSO-5.2, SSO-5.12,
SSO-9.8): the fixed order of a start and the refusal each step answers, the protocol state the package generates and
what of it is stored, the client's verifier and its challenge, the discovery fallback for a named connection that
cannot be used (SSO-3.5), the events a start reports, and the one place a request is consumed, exactly once, whatever
the race. The tables, the value types and the completion they feed are in `flows.md`; applications are in
`applications.md`.

## Invariants

### Starting a flow

- `Flows\AuthorizationRequestService::start($application, $purpose, $connectionId, $client, $codeChallenge, $caller)`,
  the client an `Http\ClientContext` the application builds from the request, answers a `Flows\StartResult`: `started`
  (reference, navigation, the generated verifier or none), `refused` (reason) or `rate_limited` (`retryAfter`). Called
  inside a transaction open on the storage connection, it is a `LogicException` before anything else
  (`StorageConnection::assertNoTransaction()`): the driver it calls may reach the identity provider, and the caller's
  transaction would keep the connection's lock all the while (SSO-11.5). Its steps run in this order, and each refusal
  reports exactly one `FlowFailed(Flow::AUTHORIZATION_REQUEST, reason)` and writes nothing:
  1. the purpose's caller (`Identities\Caller`, whose session id is 1 to 255 bytes when given): `sign_in` with no
     caller, `link` for a caller, on a session or not, `reauthenticate` for a caller on a session. Anything else is
     application code's mistake, an `InvalidArgumentException` naming the purpose's caller, before anything is counted
     or reported;
  2. the attempt, counted with `AttemptSubject::authorizationRequest()` against the IP address of the
     `Http\ClientContext` the start is given (none for a client with none, as a console command passes): a full limit is
     `rate_limited` with its wait;
  3. `Applications\ApplicationGate::admit()`: `application_not_allowed` for an unknown application and for one the
     policy does not allow, alike;
  4. the client's challenge, when given, must have an S256 challenge's form (`S256Challenge::isWellFormed()`), else
     `challenge_invalid`; with none, the package generates a `Flows\Verifier` and keeps its challenge;
  5. the connection, by exactly its id, of any tenant, read from the write connection (SSO-11.3): unknown, or not usable
     (`ProtocolManager::isUsable()`: disabled, its protocol switched off, or incomplete), is `connection_unavailable`.
     When the application offers discovery (`discoveryEnabled` and the `discovery` feature on) the failure is still
     reported, but the answer is `fallback()`: `started`, in a start's shape, leading to the application's fallback;
  6. a `link` asks `Freshness\FreshnessGate` with `sso.link.create` (SSO-2.12) for its caller, with the session it gave,
     else `freshness_required`;
  7. a `reauthenticate` asks `Contracts\ReauthenticationSessions::standing()` with the caller's identity and session and
     the connection, else
     `session_ineligible` for anything but `signed_in` (SSO-5.10); the default answers `not_signed_in` (steps 6 and 7
     are `Flows\StartEligibility::refusal()`);
  8. the connection's `trust_version`, as step 5 read it, is captured; `Flows\ProtocolState::generate()`, then the
     driver's `start()` with a `Protocols\StartRequest` (purpose, application, reference, state, nonce, PKCE verifier),
     outside any transaction the start opens; a refused `Start` is refused with the driver's reason;
  9. in a transaction on the storage connection: the connection's row is read again locked for update, the first lock
     of every flow, and when it is gone, its switch, settings or secrets changed since step 5, or its `trust_version` is
     no longer the one captured (a certificate removed meanwhile voided only the requests already stored, so this one
     must not be stored against the old trust), the start answers as step 5 does (`connection_unavailable`), writing
     nothing; otherwise the request is inserted through its
     model, and the connection's `flows_version` raised by one under the lock, so the insert also writes the
     connection's row: a PostgreSQL `REPEATABLE READ` change whose snapshot predates the request fails to serialise
     when it locks the connection, rather than void the connection's requests without it (`Connections\InFlightVoider`).
     The values are compared as cast, the settings' maps whatever their key order (a JSON column need not keep it, and
     a connection just created holds its values as given), a list's order still counting;
  10. `Events\AuthorizationRequestStarted`, dispatched after that transaction commits (`Events\AfterCommitDispatcher`);
  11. `StartResult::started($reference, $navigation, $verifier)`, the verifier only when the package generated it.
- The stored request holds `reference`; `state_digest` and `nonce_digest`, the lower-case hex SHA-256 of the state and
  the nonce, never either; `purpose`, `application`, `connection_id`; `expected_issuer`, `issuer_required` and
  `saml_request_id` as the driver's `Start` gave them; `code_verifier`, the PKCE verifier encrypted through
  `Contracts\SecretEncrypter`; `handoff_challenge`, the client's challenge or the generated verifier's; `trust_version`,
  the connection's as the start read it, which the completion compares with the connection's at consumption, before
  anything is validated or a provider called, and again under its lock (`completion.md`); `identity_type` and
  `identity_id`, the caller's identity, and `session_id`, its session for a `reauthenticate` alone
  (`Purpose::bindsSession()`): a `link` gives its caller's session to freshness and stores none; and `expires_at`, now
  plus `FlowSettings::requestTtlSeconds()` (60 to 900, default 600).
- `begin()` (steps 1, 4 and 6 to 11, for an application already admitted and a connection already found) and
  `fallback($application, $challengeGiven)` (a fresh reference, the fallback's `Navigation::toApplication()`, a fresh
  verifier unless a challenge was given, nothing stored or reported) are public for discovery and `@internal`.
  `fallback()` for an application with no fallback URL is a `LogicException`.

### Protocol state and the client's verifier

- `Flows\ProtocolState` holds three `Secrets\Secret` values, each 43 base64url characters from 32 bytes of the system's
  CSPRNG: the state (OIDC `state`, SAML `RelayState`), the nonce and the PKCE verifier. It answers `stateDigest()`,
  `nonceDigest()` and `codeChallenge()` (S256, RFC 7636 §4.2); a dump and `json_encode()` show `[redacted]` for each,
  and it refuses to be serialised or unserialised.
- The public reference, the state, the nonce, the PKCE verifier and the client's verifier are five independent random
  values (SSO-5.2, SSO-5.12). The PKCE verifier never leaves the API; the client's verifier is returned once, in the
  start response's body, when the package generated it, and only its challenge is stored.
- Every answer carries `Cache-Control: no-store` (`StartResult::headers()`), and a rate limited one `Retry-After`.

### Consuming a request

- `Flows\RequestConsumption::consume(Connection $routeConnection, Correlation $correlation)` is the only place a request
  is consumed (BL-34 calls it, after `correlate()` and before `complete()`). It runs in a transaction of its own on the
  storage connection, a savepoint inside the caller's; the completion that calls it runs outside any.
- The request is read with `lockForUpdate()` on the write connection: by `state_digest` when the correlation carries a
  state, otherwise by (`connection_id` = the route connection, `saml_request_id`), compared again in PHP exactly. A
  correlation that carries neither finds nothing, with no statement.
- None is `unknown`. `consumed_at` already set, or `SingleUseStore::record('authorization_request', $request->id,
  max(expires_at, now + 1s))` answering `seen`, is `replayed`, writing nothing. Otherwise `consumed_at` is set to now
  and the key recorded, both in the transaction, so concurrent consumptions, plain or each inside its own open
  transaction, leave exactly one `consumed`.
- An application `ApplicationRegistry::find()` no longer finds is `refused(application_not_allowed)` with no
  application, ahead of every other reason; the request is terminal, so the same write that sets `consumed_at` sets
  `completed_at` too.
- Once that commits the request is judged, in this order: a SAML request id given with a state that is not exactly
  the stored one is `refused(request_unknown)`; `voided_at` set is `refused(connection_unavailable)`; a `connection_id`
  other than the route connection's is `refused(connection_mismatch)`; `expires_at <= now` is
  `refused(request_expired)`; otherwise `consumed`, with the model, a `Protocols\ConsumedRequest` (the PKCE verifier
  still encrypted, with the `SecretEncrypter` that decrypts it into a `Secret` only when the driver calls
  `codeVerifier()` to build the token request, so a SAML completion never decrypts it, the nonce digest, the issuer
  data, the SAML request id, `startedAt` = `created_at`) and the `Applications\Application`. Every `refused` but the
  first keeps the application, so the completion can redirect to it.
- `Flows\ConsumptionResult` (`Flows\Enums\ConsumptionStatus`: `consumed`, `refused`, `unknown`, `replayed`) carries
  `request`, `consumed`, `application` and `reason` as they apply (`request_unknown` for `unknown` and `replayed`), and
  `hasRedirectTarget()`, true only when it carries the application. It shows only its status, reference, application
  name and reason in a dump, and refuses to be serialised or unserialised. A dumper that shows every property whatever
  `__debugInfo()` answers, as `dump()` does, shows the request's columns, its digests and the verifier's ciphertext
  among them, and never the PKCE verifier, which is decrypted only into a `Secrets\Secret`.
- The consumption reports nothing: the completion reports how it ended.

### Events

- `Flows\RequestEvents` builds every context through `Events\EventContexts` and dispatches after commit.
  `AuthorizationRequestStarted` names the connection, its tenant and protocol, the application, the purpose, the
  `request_reference`, and the identity and session stored. A `FlowFailed` names the purpose, the caller's identity and,
  for a `reauthenticate`, its session, and what the start had established: the application once admitted, the connection
  once found, the reference once generated. An application name that was not admitted is never reported.
- The public reference is the only flow identifier either carries (SSO-9.8): never the state, the nonce, a verifier, a
  challenge, a digest or a SAML request id.

## Success Path

1. The application calls `start('web', Purpose::SIGN_IN, $connectionId)` from its start route; the attempt is counted,
   `web` admitted, a verifier generated, the connection found usable, the driver asked to start, and the request stored
   under the connection's lock.
2. Once the start's transaction commits, `AuthorizationRequestStarted` is reported, and the start answers `started` with
   `{reference, navigation, verifier}` and `Cache-Control: no-store`.
3. The identity provider's response arrives at the connection's endpoint; the completion reads its correlation and calls
   `consume()`, which consumes the request once and answers `consumed` with the `ConsumedRequest` the driver validates
   the response against.

## Failure / Edge Cases

- A misbound purpose is an `InvalidArgumentException`; nothing is counted, asked, written or reported.
- Each refusal writes no request and reports exactly one `FlowFailed`; a discovery fallback reports exactly one
  `FlowFailed(connection_unavailable)` and answers `started`, with a reference that names no request.
- A connection disabled, re-trusted or deleted while the driver started: the start's locked re-read sees the change and
  answers `connection_unavailable`, so a change that voided the connection's requests can never miss one stored after
  it. A change committed after the insert voids the request itself (BL-37).
- A start called inside a transaction open on the storage connection is a `LogicException`; nothing is counted,
  asked, written or reported.
- A driver that answers a SAML request id the connection already holds is a driver's bug: the unique violation
  propagates. A database error, a store that cannot answer and a malformed setting all propagate (SSO-11.4); a PKCE
  verifier's ciphertext no key decrypts propagates from `codeVerifier()`, once the request is consumed, and only for a
  driver that asks for it.
- A request is consumed whether its response then passes or fails; a second response for it, from any server, is
  `replayed`, as is one the single-use store has seen. A response whose SAML request id contradicts its state consumes
  the request it names and is refused.

## Implementation Anchors

- `src/Flows/AuthorizationRequestService.php`, `src/Flows/ProtocolState.php`, `src/Flows/RequestEvents.php`.
- `src/Flows/RequestConsumption.php`, `src/Flows/ConsumptionResult.php`, `src/Flows/Enums/ConsumptionStatus.php`.
- `src/Flows/StartResult.php`, `src/Flows/Verifier.php`, `src/Flows/S256Challenge.php`,
  `src/Flows/RequestReference.php`, `src/Flows/FlowSettings.php`, `src/Models/AuthorizationRequest.php`,
  `src/Protocols/StartRequest.php`, `src/Protocols/ConsumedRequest.php`, `src/Protocols/Correlation.php`.

## Authoritative Tests

- `tests/Unit/Flows/ProtocolStateTest.php`, `tests/Unit/Flows/ConsumptionResultTest.php`,
  `tests/Unit/Protocols/ConsumedRequestTest.php` (the verifier decrypted only when asked for).
- `tests/Feature/Flows/AuthorizationRequestServiceTest.php`, `tests/Feature/Flows/StartEventSequenceTest.php`,
  `tests/Feature/Flows/RequestConsumptionTest.php`.
- `tests/Integration/Flows/ConcurrentRequestConsumptionTest.php`, `tests/Integration/Flows/StartAfterCommitTest.php`
  (a start inside a caller's transaction refused), `tests/Integration/Flows/StartTrustChangeRaceTest.php` (a trust
  change between the start's read and its insert, across processes on MySQL and PostgreSQL).
- `tests/Performance/AuthorizationRequestQueryBudgetTest.php`; the fixtures
  `tests/Fixtures/Protocols/StartingDriver.php` and `tests/Fixtures/Secrets/CountingSecretEncrypter.php`.

## Change Triggers

- A step added to, removed from or moved in a start, or a change to what a step refuses with.
- A change to what the request stores, to the protocol state's form, or to what of the connection the locked re-read
  compares.
- A change to how a request is looked up, consumed, recorded in the single-use store or judged, or to the order of the
  judgement.
- A change to what an event's context names.
