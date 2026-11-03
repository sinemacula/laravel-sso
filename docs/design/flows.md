# Flow Core

## Purpose

This note records the parts of the links and flow core (P3) that every flow shares, so links, authorisation requests,
discovery, completion, handoff codes, completion responses and connection lifecycle changes are built on one model:
the three tables and their models, the distinct value types that cross a flow, the verified result, the contracts and
their fail-closed defaults, the completion's fixed steps and the transaction each runs in, the lock order, the failure
reasons by flow and the events each operation reports. Each part's own behaviour is in its own note (`links.md`,
`authorization-requests.md`, `discovery.md`, `completion.md`, `handoffs.md`, `completion-responses.md`,
`connection-lifecycle.md`); applications and endpoints are in `applications.md`.

## Invariants

### Tables and models

- `sso.links.table` (`sso_links`, `Models\Link`): `connection_id`; `issuer` (up to 1024) and `name_id_format` (up to
  255, SAML only), kept as received; `subject`, byte for byte in a binary column (`Models\Casts\BinaryString`: a
  stream on PostgreSQL, a string elsewhere); `subject_key`, the lower-case hex SHA-256 of the issuer, the format and the
  subject, each length-prefixed, unique with `connection_id`, the only column a lookup compares, so no collation can
  fold or trim a subject; `identity_type` and `identity_id`; `state` (`Links\Enums\LinkState`: `active`, `reserved`,
  `suspended`) with `suspended_at`; `provenance` (`Links\Enums\LinkOrigin`), from which `domain_provenance` is read; a
  reservation's binding (`linking.md`); `last_used_at`, `created_at`, `updated_at`. The connection, issuer, format,
  subject and key are fixed once
  the link exists (`LogicException`). Indexed by (`identity_type`, `identity_id`, `connection_id`) for listing and the
  link limit.
- `sso.authorization_requests.table` (`sso_authorization_requests`, `Models\AuthorizationRequest`): `reference`, the
  public reference, unique; `state_digest`, the SHA-256 of the random protocol state, unique, never the state;
  `purpose`, `application`, `connection_id`; `expected_issuer`, `issuer_required`; `nonce_digest`; `code_verifier`, the
  PKCE verifier used with the identity provider, encrypted through `Contracts\SecretEncrypter`; `saml_request_id`,
  unique with the connection; `handoff_challenge`, the client's S256 challenge; `trust_version`, the connection's trust
  version as the start read it, compared at consumption and again under the completion's lock; `identity_type`,
  `identity_id` (`link`, `reauthenticate`) and `session_id` (`reauthenticate`); `expires_at`, and `consumed_at` (a
  completion consumed it), `verified_at` (its response was verified and recorded against replay, at the provisioning
  boundary), `voided_at` (a change to its connection voided it) and `completed_at` (its completion
  finished, either way).
- `sso.handoff_codes.table` (`sso_handoff_codes`, `Models\HandoffCode`): `code_digest`, unique, never the code; what the
  code is bound to: `purpose`, `application`, `connection_id`, `request_reference`, `handoff_challenge`, `identity_type`
  and `identity_id` (the flow's identity), `session_id`, `linked_identity_type`, `linked_identity_id` and `link_id`
  (what the result's link resolved to at completion, and through which link), `reservation_id` (the reservation it
  holds); `result`, the serialised verified result, encrypted; `session_not_after` (SSO-9.10); `expires_at`,
  `redeemed_at`, `voided_at`.
- Every model is keyed by a lower-case ULID and stamped from the package's clock (`SsoModel::identifiedAndStamped()`),
  hidden columns (digests, ciphertexts) never serialise, and no model carries behaviour: a reader builds an identity
  from two columns with `Identities\IdentityReference::fromColumns()`. There is no foreign key: a connection's deletion
  deletes its rows in its own transaction, whatever the engine. A lookup by `reference` or `saml_request_id` compares
  again in PHP, exactly, since MySQL's default collation folds case.
- Every read that decides a flow is made on the write connection (SSO-11.3); every write goes through the model.

### Value types

- `Flows\RequestReference`: 32 base64url characters from 24 random bytes, under the 40 the log sanitiser redacts; not a
  secret, the only flow identifier in events and logs, under `request_reference` (SSO-9.8).
- `Flows\Verifier`: 43 to 128 unreserved characters (RFC 7636 §4.1); a generated one is 43 characters from 32 random
  bytes, returned once in the start response's body. Held in a `\SensitiveParameterValue` behind `reveal()`, with a
  redacted dump and JSON form, no `__toString()`, and no (un)serialisation; compared in constant time.
- `Flows\S256Challenge`: `BASE64URL(SHA-256(verifier))` without padding, 43 characters; satisfied only by its verifier,
  compared in constant time.
- `Handoffs\HandoffCode`: 43 base64url characters from 32 random bytes; held like a verifier; stored only as
  `digest()`, matched with `matches($digest)` in constant time.
- The protocol state (OIDC `state`, SAML `RelayState`) and the nonce are `Secrets\Secret` values; only their digests are
  stored. None of these types is accepted as another, nor as a token (SSO-9.2, AUTH-5.7).

### Verified result

- `Results\VerifiedResult` (SSO-8.1): `issuer`, `subject`, `nameIdFormat`, `connectionId`, `tenantId`, `protocol`,
  `application`, `purpose`, `requestReference`, the mapped `attributes` (strings or lists of strings), whether the
  email's domain is verified for the connection, the `Results\AuthenticationContext` (authentication time, methods,
  context class, provider session id and deadline) and the optional `Results\LinkingEmail` (email, source, accepted
  organisation). The issuer and subject are 1 to 1024 bytes, exactly as received (SSO-6.9).
- It is serialisable, as SSO-8.1 requires: `toArray()`, `serialize()` and `json_encode()` write the same stored form,
  holding everything above and nothing else; `restore()` and `unserialize()` check every part again and fail with an
  `UnexpectedValueException` on anything the package did not write. It is read back only from the package's own
  encrypted storage, never from client input, and never handed to an event whole.
- `Results\VerifiedClaims` is what a driver verified (issuer, subject, format, raw attributes by provider name,
  authentication context, linking email); it lives only for its completion (no serialisation, a dump shows attribute
  names only).
- `VerifiedClaims`, `AuthenticationContext` and `LinkingEmail` hold provider values in public properties, so each
  writes a redacted projection to `json_encode()`, which is also what a Monolog formatter's normaliser and any other
  JSON-based logger write of it: the claims' issuer, NameID format, each attribute's name with the kind of its value
  (`string`, `array`, `int`...), and the redacted forms of their context and linking email; the context's parts as
  `[redacted]` when stated and `null` when not, with the number of methods; the linking email's source, with its email
  and organisation `[redacted]`. Never the subject or a value the provider asserted. `toArray()` stays the stored form
  of the context and the linking email, which `VerifiedResult::toArray()` builds on, so a verified result's storage
  serialisation is unchanged.

### Contracts and defaults

| Contract                   | Default                                      | Fails closed by                              |
|----------------------------|----------------------------------------------|----------------------------------------------|
| `ApplicationPolicy`        | `Applications\ConfiguredApplicationPolicy`   | `external_sign_in` off unless set            |
| `RedirectUriResolver`      | `Applications\ConfiguredRedirectUriResolver` | the configured URI, checked exactly          |
| `EndpointResolver`         | `Endpoints\ConfiguredEndpointResolver`       | configuration only, never the request        |
| `Linker`                   | `Links\NoLinks`                              | linking nothing                              |
| `LinkLimit`                | `Links\OneLinkPerConnection`                 | one link per identity per connection         |
| `LinkEligibility`          | `Linking\RefusingLinkEligibility`            | refusing every identity                      |
| `LinkConfirmation`         | `Linking\RefusingLinkConfirmation`           | no caller counts as independent              |
| `LinkEmailMatcher`         | `Linking\NoEmailMatches`                     | finding no identity                          |
| `PrincipalScope`           | `Linking\RefusingPrincipalScope`             | `unknown` for every identity                 |
| `TenantMembership`         | `Linking\NoTenantMembership`                 | no membership that counts                    |
| `EvidencePolicy`           | `Evidence\InsufficientEvidence`              | accepting nothing                            |
| `ReauthenticationSessions` | `Flows\NoReauthenticationSessions`           | `not_signed_in` for every question           |
| `ProviderSessionDeadline`  | `Results\ProviderDeadlineLimitsSession`      | the deadline limits the session              |
| `HandoffIssuer`            | `Handoffs\DatabaseHandoffStore`              | the package's own store                      |
| `CompletionStage`          | one class per step                           | a stage refuses as a value, errors propagate |

Each is bound with `singletonIf` when it holds nothing and `scopedIf` when it reads configuration or a connection, so an
earlier binding is kept and nothing outlives a request (SSO-11.2).

### The completion

- `Contracts\ProtocolDriver` is split for it: `correlate()` reads which request a response answers
  (`Protocols\Correlation`: `solicited` with the state and/or the SAML request id, `unsolicited`, `uncorrelated`)
  without validating anything; `complete()` validates against the `Protocols\ConsumedRequest` (purpose, application,
  reference, start time, expected issuer and `iss` requirement, SAML request id, nonce digest matched by `isNonce()`,
  the PKCE verifier, decrypted only when the driver asks for it with `codeVerifier()` to build the token request) and
  answers `Protocols\Completion::verified(VerifiedClaims)` or `refused(FailureReason)`.
  `Protocols\Start` keeps what a request stores, typed: `samlRequestId`, `expectedIssuer`, `issuerRequired`.
- The steps run in `Completion\Enums\CompletionStep`'s order: `correlation`, `consumption`, `validation`,
  `replay_recording`, `link_resolution`, `enforcement`, `purpose_rules`, `domain_reservation`, `provisioning`,
  `unlinked_decision`, `handoff_issuance`. Each is a `Contracts\CompletionStage` taking and returning a
  `Completion\CompletionState` through
  a `Completion\StageOutcome` (`proceed`, `refuse` with a reason, or, from `correlation` alone, `reinitiate` for an
  unsolicited SAML response, or, from `provisioning` alone, `provision` for the boundary of `linking.md`; the state kept
  either way).
- Transactions: a completion, and a start (named or by discovery), run outside any transaction on the storage
  connection; called inside one, each is a `LogicException` at entry, before anything is written, so a caller's rollback
  never undoes a consumption (SSO-5.1) and a caller's transaction never keeps the connection's lock across a call to the
  driver (SSO-11.5). A redemption, by decision D5, may run inside the redeemer's. `correlation` and `validation` run
  outside any transaction the pipeline opens (validation may fetch); `consumption` runs in a transaction of its own on
  the storage connection, which locks the connection's row before the request's, as every transaction here does, so the
  request is consumed whether the response then passes or fails; every step from `replay_recording` on runs in one
  transaction on the storage connection that first locks the tenant's enforcement (when it applies, see the lock order),
  then the connection's row (with the rule's connections) and then the request's row, and refuses if the connection is
  no longer usable, the request was voided since consumption or its stored trust version is no longer the connection's,
  or the enforcing tenant moved since its rule was locked. The trust version is stored on every request at start
  (compared under the connection's lock before the insert), checked at consumption against the locked connection
  before validation or any provider call, and checked again under the completion's lock. One exception, and only one,
  crosses a trust version: the sign-in whose own token triggered an unknown-`kid` refetch that removed a key may finish
  across exactly that transition, on a `Protocols\TransitionReceipt` judged at those locks (`oidc-driver.md`); it never
  restores a voided request and never adopts a later trust version.
  A genuinely unlinked `sign_in` stops that transaction at the provisioning boundary and finishes in a final
  continuation, with the unlinked-result event dispatched between them (`linking.md`). Events are dispatched after their
  transaction commits (or after the consumption's, for a refusal before it), never on a rollback, except that one.
- `Completion\CompletionResult` is how a completion ended: `completed` (redirect URI, delivery, reference, issued
  handoff), `failed` (reason, redirect URI, delivery, reference), `rejected` (reason, no trusted target: a 400),
  `rate_limited` (`retryAfter`: a 429) or `reinitiated` (the connection's start URL, SSO-5.8). It may hold the code, so
  it shows none in a dump and refuses serialisation.
- `Handoffs\HandoffGrant` is what a code is issued for: the result (which names purpose, application, connection and
  reference), the challenge, the expiry, the linked identity, the flow's identity (`link`, `reauthenticate`) and session
  (`reauthenticate`) and the session's latest end; a grant whose identity or session does not fit its purpose is
  refused. `Handoffs\IssuedHandoff` is the code and its expiry.

### Lock order

An identity's guard, for what changes its verified domain links; a tenant's enforcement row; connection rows in
ascending id order; then their rows in the other tables: domains (P2), requests, codes, links; then the application's
guards.

- The identity's guard (`Linking\IdentityLock`, `sso_identity_guards`) comes first in a principal widening, a
  reservation, the redemption of a code bound to a reservation (its activation), and every `link` redemption, whether it
  confirms a link, creates one or is refused, and whether or not the `domain_linking` feature is on: a `link` is
  confirmed against the identity's verified domain links, held now or before. Nothing else takes it: an ordinary linked
  sign-in, a `reauthenticate` and a sign-in with no reservation never do. It amends the order this note first set, for
  the reason `linking.md` records: what is about to be changed is found by plain reads, locked in this order, and judged
  again under the locks. The application's principal-change transaction calls `Linking\ScopeWidening::widened()` first,
  then its own guard and its write, so a racing reservation or activation cannot slip past it. See `linking.md` for each
  flow's discovery and what it does when the candidates changed.
- The enforcement row comes first wherever a rule is changed or an admission is judged against one: the enforcement
  change (P2), a redemption (`HandoffRecheck::lock()`, before the code), and the locked steps of a completion (at the
  start of `CompletionPipeline::finish()`, before the request). An admission takes it only under the default
  `DatabaseEnforcement` with the `enforcement` feature on, and locks the row of the enforcing tenant the inheritance
  contract names. A tenant with no row has one inserted unconfigured (`Enforcement\EnforcementLock`: an upsert that
  never changes an existing row, then a locking read), which reads everywhere as no row, so racing first lockers queue
  on the row rather than deadlock on MySQL's gap locks.
- The connections come next in one locking statement ordered by id: the admission's own connection with every
  connection the rule names (the union), so a disable of a satisfying connection is ordered too.
- Anything learnt before the locks to choose them (the code's connection and application, the connection's tenant,
  the enforcing tenant) is confirmed once they are held: a code that names another connection or application is
  `handoff_unknown`, a connection gone or of another tenant `connection_unavailable`, and an inheritance contract that
  names another tenant now is `connection_unavailable`; a different enforcement row is never locked out of order.
- With the feature off, or another enforcement contract bound, no enforcement row is locked, read or inserted, and the
  inheritance contract is not asked.

Every re-read under a lock that decides a write is a locking read (`lockForUpdate()`), since a caller's MySQL REPEATABLE
READ transaction answers a plain read from an older snapshot, and an answer reached before the lock ("unchanged",
"already done", the state a slow step was based on) is confirmed under it. On PostgreSQL under `REPEATABLE READ`, a
transaction fails to serialise (SQLSTATE `40001`) only when it locks a row that a transaction committed since its
snapshot updated or deleted; a row that was only locked raises nothing, and a row inserted since stays invisible to it.
So a writer whose insert a later locker must see also writes the row they both lock: a link's creation raises its
connection's `links_version` (`Links\LinkStore::create()`), so a subject migration that locks the connection after it
fails to serialise rather than miss the link; a stored authorisation request and an issued handoff code each raise their
connection's `flows_version` (`Flows\AuthorizationRequestService`, `Handoffs\DatabaseHandoffStore`), so a change that
voids the connection's flows (`Connections\InFlightVoider`) and locks the connection after either fails to serialise
rather than leave the new request or code unvoided; and the identity's guard is written by every locker, so one whose
snapshot predates another's commit fails to serialise rather than miss what that one did. The failure propagates, and a
caller retries its whole transaction, never a part of it.

### Start

`Flows\StartResult` answers a start (`started` with reference, navigation and the generated verifier, `refused`, or
`rate_limited`), with `body()` (`{reference, navigation, verifier?}`, the one place a verifier is revealed, or
`{error, retry_after?}`) and `headers()` (`Cache-Control: no-store`, and `Retry-After`). `body()` carries the
navigation whole, as `Protocols\Navigation::jsonSerialize()` gives it; a dump of the result shows no verifier, and the
navigation only as the navigation's own dump does, its URL's query values and fragment and its fields' values
redacted, so no `state`, `nonce`, `code_challenge`, `SAMLRequest` or `RelayState` reaches a dump. A discovery miss and a
start naming an unknown or disabled connection for an application that offers discovery answer `started`, with the
fallback's navigation (`Protocols\Navigation::toApplication()`), a reference and a verifier in the same shape.
`Flows\FlowSettings` reads `sso.authorization_requests.ttl_seconds` (60 to 900, default 600) and
`sso.discovery.minimum_duration_milliseconds` (50 to 2000, default 250); `[flows]` checks both at boot.

### Failure reasons by flow

- Authorisation request (`Flow::AUTHORIZATION_REQUEST`): `application_not_allowed`, `connection_unavailable`,
  `challenge_invalid`, `freshness_required` (`link`), `session_ineligible` (`reauthenticate`), `discovery_no_match`,
  `rate_limited`.
- Assertion and callback (`Flow::ASSERTION`, `Flow::CALLBACK`): `connection_unavailable`, `connection_mismatch`,
  `request_unknown`, `request_expired`, every validation reason of P4 and P5, `enforcement_unsatisfied`,
  `link_suspended` (a `sign_in` or a `reauthenticate`), `principal_scope_unknown` (a `sign_in`, a `link` or a
  `reauthenticate`), `link_reserved` (a `sign_in` or a `link`),
  `link_ineligible` and `subject_already_linked` (`link`), `identity_mismatch` and `authentication_expired`
  (`reauthenticate`), `unlinked`, `application_not_allowed`, `rate_limited`.
- Redemption (`Flow::REDEMPTION`): `handoff_unknown`, `handoff_expired`, `replayed`, `purpose_mismatch`,
  `application_mismatch`, `connection_mismatch`, `verifier_mismatch`, `connection_unavailable`,
  `enforcement_unsatisfied`, `link_changed`, `link_suspended`, `principal_scope_unknown`, `link_reserved`,
  `reservation_invalid`,
  `identity_mismatch`, `freshness_required`, `link_ineligible`, `independent_authentication_required`,
  `subject_already_linked`, `link_limit_reached`,
  `session_ineligible`, `authentication_expired`, `application_not_allowed`, `rate_limited`.
- Administration (a helper's result, no event): `link_not_found`, `link_limit_reached`, `subject_already_linked`,
  `connection_has_links`, `links_unaccounted`, with P1's `freshness_required` and `connection_not_found`.

### Events

`Events\AuthorizationRequestStarted`, `Events\ResultVerified`, `Events\HandoffIssued`, `Events\HandoffRedeemed`,
`Events\LinkCreated` (with `Links\Enums\LinkOrigin`: `link_purpose`, `provisioning`, `verified_domain`, `migration`) and
`Events\LinkRemoved`, `Events\LinkActivated`, `Events\LinkConfirmed`, `Events\LinkSuspended` and
`Events\ReauthenticationCompleted`, each carrying only an `EventContext` and at most an id; every refused start,
completion and redemption fires exactly one `Events\FlowFailed`. No event holds a code, verifier, state, nonce, subject,
attribute or result, but for `Events\ResultUnlinked`, the one event dispatched synchronously and carrying the result
and its provisioning grant (`linking.md`).

## Success Path

1. A start admits the application, resolves the connection, generates the state, nonce and PKCE verifier, asks the
   driver to start, stores the request, and answers `started` with `Cache-Control: no-store`
   (`AuthorizationRequestStarted`).
2. A completion correlates, consumes, validates, resolves the link, checks enforcement, decides an unlinked sign-in,
   asks the policy again and issues the code under the connection's lock (`ResultVerified`, `HandoffIssued`), and
   answers `completed`.
3. A redemption with the code, application, connection and verifier consumes the code once, rechecks the connection,
   enforcement and link, and answers the result (`HandoffRedeemed`).

## Failure / Edge Cases

- A request or a code is consumed exactly once, through the single-use store and a locked row, whatever the race; a
  request's consumption is never inside a caller's transaction (a completion there is refused), and a code's, inside a
  redeemer's, is undone only with the redemption it belongs to; a replay is refused.
- A disable or trust change voids every unfinished request and every unredeemed code of the connection in its own
  transaction; a completion that consumed a request before the change refuses it under the lock afterwards. A
  callback's own key rotation spares that one consumed request, in the same transaction that voids the rest and records
  the transition for it in memory alone; a process that dies before its final locks leaves the request consumed and
  never completed, which nothing can complete, since the receipt died with it.
- A database error is never a refusal: it propagates as a server error (SSO-11.4).

## Implementation Anchors

- `database/migrations/2026_11_03_000003_create_sso_identity_guards_table.php`,
  `database/migrations/2026_11_03_000000_create_sso_links_table.php`,
  `database/migrations/2026_11_03_000001_create_sso_authorization_requests_table.php`,
  `database/migrations/2026_11_03_000002_create_sso_handoff_codes_table.php`; `src/Models/Link.php`,
  `src/Models/AuthorizationRequest.php`, `src/Models/HandoffCode.php`, `src/Models/Casts/BinaryString.php`.
- `src/Flows/`, `src/Handoffs/HandoffCode.php`, `src/Handoffs/HandoffGrant.php`, `src/Handoffs/IssuedHandoff.php`,
  `src/Results/`, `src/Links/`, `src/Completion/`.
- `src/Contracts/` (the contracts above), `src/Protocols/Correlation.php`, `src/Protocols/ConsumedRequest.php`,
  `src/Protocols/Completion.php`, `src/Protocols/Start.php`.
- `src/Events/Enums/FailureReason.php`, the six events, `src/SsoServiceProvider.php`.

## Authoritative Tests

- `tests/Integration/Flows/FlowTablesMigrationTest.php`, `tests/Feature/Models/FlowModelsTest.php`,
  `tests/Feature/Models/Casts/BinaryStringTest.php`.
- `tests/Unit/Flows/`, `tests/Unit/Handoffs/`, `tests/Unit/Results/`, `tests/Unit/Protocols/CorrelationTest.php`,
  `tests/Unit/Protocols/ConsumedRequestTest.php`, `tests/Unit/Completion/CompletionResultTest.php`,
  `tests/Feature/Completion/CompletionStateTest.php`, `tests/Unit/Events/FlowEventClassesTest.php`,
  `tests/Feature/Results/ResultPartsLoggingTest.php` (no provider value in a result part's JSON or logged context).
- `tests/Feature/Flows/FlowsCheckTest.php`, `tests/Feature/SsoServiceProviderTest.php`.

## Change Triggers

- A new table, column or index; a change to a value type's form or to what the verified result holds.
- A new contract, a change to a default, or a step added to, removed from or moved in the completion.
- A change to the lock order or to which transaction a step runs in.
