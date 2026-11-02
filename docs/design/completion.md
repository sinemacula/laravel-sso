# Completion

## Purpose

This note records how a flow completes where the identity provider sends the browser back (SSO-5.5, SSO-5.6, SSO-5.7,
SSO-6.10, SSO-8.1, SSO-8.6, SSO-9.2, SSO-12.1): the two helpers and what they check before the steps run, the stage
behind each step and what it decides, the verified result and how it is built, the transactions and the locks, how a
completion ends and what it reports. The steps, the tables, the value types and the lock order are in `flows.md`;
consuming a request is in `authorization-requests.md`; the response values are in `completion-responses.md`.

## Invariants

### The helpers

- `Completion\CompletionService` (`@api`, resolved per request) has one call per endpoint, each answering a
  `Completion\CompletionResult`:
  - `assertionConsumerService($connectionId, CompletionRequest $request)`: `Flow::ASSERTION`, `POST` only;
  - `callback($connectionId, CompletionRequest $request)`: `Flow::CALLBACK`, `GET` only.
- The connection id is the one the application's route names; the route's URL is the endpoint resolver's, built from
  configuration and never from the request (SSO-5.5). Before the steps run, in this order, each refusal reporting
  exactly one `FlowFailed` and writing nothing:
  1. the completion is counted with `AttemptSubject::completion()` against the IP address of the request being served
     (none in a console) and the connection id (SSO-11.8); a full limit is `rate_limited` with its wait;
  2. the method must be the endpoint's, compared exactly (`POST`, `GET`); anything else is `rejected(request_unknown)`;
  3. the connection is read by exactly its id, of any tenant, from the write connection (SSO-11.3); an empty id or one
     longer than a ULID is not looked up, and a row the collation merely counts as equal is not found; an unknown one is
     `rejected(connection_unavailable)`;
  4. its protocol must complete at the endpoint: `saml2` at the assertion consumer service, `oidc` at the callback, and
     a protocol an application registered with `extend()`, which the package cannot place, at either while its driver
     is registered; anything else is `rejected(connection_unavailable)`.
- A connection that is not usable is not refused here: a disabled connection still consumes the request its response
  names, and its failure is redirected to the request's application (SSO-5.7).

### The stages

`Completion\CompletionPipeline::stageClass()` maps each `Completion\Enums\CompletionStep`, in the cases' order, to the
`Contracts\CompletionStage` the container resolves for it per completion:

| Step                 | Stage               | Goes on with, or refuses with                                            |
|----------------------|---------------------|--------------------------------------------------------------------------|
| `correlation`        | `CorrelateResponse` | the solicited correlation; `request_unknown`                             |
| `consumption`        | `ConsumeRequest`    | the request and its application; the consumption's reason                |
| `validation`         | `ValidateResponse`  | the claims and the result; `connection_unavailable`; the driver's reason |
| `replay_recording`   | `RecordReplay`      | the state unchanged; `replayed`, `assertion_expired`                     |
| `link_resolution`    | `ResolveLink`       | the identity the linker resolves, if any                                 |
| `enforcement`        | `CheckEnforcement`  | the policy's version, if any; `enforcement_unsatisfied`                  |
| `domain_reservation` | `DomainReservation` | the state unchanged, until P6                                            |
| `provisioning`       | `Provisioning`      | the state unchanged, until P6                                            |
| `unlinked_decision`  | `DecideUnlinked`    | the state unchanged; `unlinked`                                          |
| `handoff_issuance`   | `IssueHandoff`      | the session's latest end and the handoff; `application_not_allowed`      |

Each stage is in `Completion\Stages`.

- `CorrelateResponse` asks the connection's driver to `correlate()`. An uncorrelated response is `request_unknown`. An
  unsolicited response at a driver that re-initiates (`Contracts\ReinitiatingDriver`, the SAML driver) is handed over
  with `StageOutcome::reinitiate()`: no further step runs, no request is consumed, and
  `Completion\UnsolicitedReinitiation` answers it (see `idp-initiated.md`). Any other driver's unsolicited response is
  `request_unknown`.
- `ConsumeRequest` calls `Flows\RequestConsumption::consume()` inside a transaction of its own on the storage connection
  that first locks the row of the connection the response arrived for, so a completion takes the connection's lock
  before its request's, in the package's order (see "Transactions and locks" below). `consumed`
  goes on; `unknown` and `replayed` are `request_unknown` with no target; `refused` keeps its reason and, while the
  request's application is still registered, the request and the application, so the failure is redirected. A refused
  request is kept as a `Protocols\ConsumedRequest` without its nonce digest or its PKCE verifier. A consumed one keeps
  the verifier encrypted: it is decrypted only when the driver calls `codeVerifier()` to build the token request, so a
  SAML completion never decrypts it.
- `ValidateResponse` refuses a connection that is no longer usable (`ProtocolManager::isUsable()`) with
  `connection_unavailable` before its driver is asked, so no provider is contacted (no OIDC token request) for a
  connection that cannot complete; otherwise it asks the driver to `complete()` against the consumed request. A refusal
  keeps the driver's reason; a verified response goes on with its `Results\VerifiedClaims` and the result built from
  them.
- `RecordReplay`, the first locked step, records what the driver asked to record against replay
  (`Protocols\ReplayRecord` on the verified completion: a SAML assertion's id, by connection and issuer, SSO-6.6)
  through the single-use store until its expiry, inside the locked transaction, so it runs only after the driver's
  validation passed, before any downstream effect, and a completion that rolls back records nothing. A repeat is
  `replayed`; a record whose expiry is no longer after now is `assertion_expired`, recording nothing. A completion
  that asked for no record goes on (see `saml-responses.md`).
- `ResolveLink` asks the bound `Contracts\Linker`; only the connection, issuer and subject select an identity (SSO-8.2).
- `CheckEnforcement` judges the policy of the connection's tenant on the request's application. Under the default
  `DatabaseEnforcement` with the feature on, it is the policy the pipeline judged from the rows it locked at the start
  of the locked transaction, carried on the state (`CompletionState::$enforcementPolicy`), so nothing is read again;
  with another contract bound, that contract is asked now, and must itself serialise against its rule's changes.
  `EnforcementPolicy::isSatisfiedBy()` is the whole rule: a policy that requires nothing is satisfied by every
  connection, one that requires sign-in only by its connections. A satisfied policy's version, when it has one, goes on
  for the handoff (SSO-4.6, SSO-9.10). No exemption is consulted at completion: an exemption admits a session, and the
  redemption rechecks enforcement against the state then.
- `DecideUnlinked` refuses a `sign_in` whose result resolved to no identity with `unlinked` unless the application
  allows unlinked handoffs (SSO-8.6). `link` and `reauthenticate` pass unchanged: their identity rules are P6's.
- `IssueHandoff` asks `Contracts\ApplicationPolicy` again (SSO-9.2): anything but `allowed` is
  `application_not_allowed`. A result carrying the provider's session deadline asks `Contracts\ProviderSessionDeadline`;
  `limits_session` makes the deadline the session's latest end (SSO-6.10); a result with no deadline never asks. It then
  issues through `Contracts\HandoffIssuer` a `Handoffs\HandoffGrant` of the result, the request's S256 challenge, an
  expiry of the application's `handoff_ttl_seconds` from now, the linked identity, the request's identity and session,
  the enforcement version and the session's latest end.
- A stage run before the steps it needs throws a `LogicException` naming what it needs: the pipeline's mistake.

### The verified result

`Completion\ResultBuilder::build($claims, $connection, $consumed)` is the only place a `Results\VerifiedResult` is
made, from what a driver verified and never from client input (SSO-8.1):

- the issuer, subject, NameID format, authentication context and linking email are the claims', exactly as verified;
- the connection id, tenant and protocol are the connection's; the application, purpose and reference the request's;
- the attributes are `AttributeMapping::fromArray($protocol, $connection->attribute_mapping, MappingLimits)` applied to
  the claims' raw attributes, so `sso.mapping`'s caps cut them;
- `emailDomainVerified` is true exactly when the mapped `email` is a string with a local part, an `@` and, after the
  last `@`, a domain that `Domains\DomainName::normalize()` accepts, and this same connection's claim of that domain
  routes now (`Domains\DomainStanding::routes()`: verified and before its lapse). A domain of another connection, a
  pending or lapsed claim, a claim at or past its lapse, and anything that is not an email are not verified. The claim
  is read through `Domains\DomainFinder` on the write connection.

### Transactions and locks

- A completion runs outside any transaction on the storage connection. `CompletionService` checks at entry, before
  anything is written (the attempt included), and called inside one it is a `LogicException`
  (`StorageConnection::assertNoTransaction()`). A caller's rollback would otherwise undo the request's consumption
  (its `consumed_at` and its single-use record), so the same response could be replayed against a request SSO-5.1
  says is consumed; and the caller's transaction would keep the connection's lock, taken by the consumption, across
  the driver's validation, which may fetch (SSO-11.5).
- Correlation, consumption and validation run outside any transaction the pipeline opens; the consumption opens its
  own, so the request is consumed whether the response then passes or fails, and it commits before the driver
  validates (a fetch is never made inside a transaction). The consumption judges the request against the connection's
  row as its locking read gives it: a request whose `trust_version` (stored at start) is not the connection's is
  refused `connection_unavailable`, the reason a voided request is refused with, so no response is validated and no
  provider called for a flow a trust change has overtaken.
- Once a request is consumed with a trusted target, one transaction on the storage connection takes `flows.md`'s lock
  order. For a completion still going on, under `DatabaseEnforcement` with the `enforcement` feature on, it first calls
  `DatabaseEnforcement::lock()` at the start of `CompletionPipeline::finish()`: the enforcing tenant's row (named by the
  inheritance contract, inserted unconfigured when it has none) and then, in one statement in ascending id order, the
  connection and the connections the rule names. Otherwise (feature off, another contract bound, or a completion already
  refused) it locks the connection's row alone, with no enforcement statement and no inheritance call. Then the
  request's row. Each is a locking read on the write connection, so none answers from an older `REPEATABLE READ`
  snapshot. A completion still going on is refused with `connection_unavailable` when the connection is gone or no
  longer usable, when the request is gone, its `voided_at` is set or its `trust_version` is not the locked connection's,
  or when the inheritance contract, asked again, no longer names the tenant whose rule is locked: validation was based
  on the connection and the request as they were before, and a change since (a disable, a trust change that voids the
  connection's requests, BL-37) wins. It is refused with `metadata_expired` when what a metadata refresh applied to the
  locked connection has expired by now (`Metadata\MetadataExpiry`, SSO-2.8): metadata that lapses, by its `validUntil`
  or the stale limit, while the response is validated is never used. Otherwise every locked step runs in that
  transaction, on the rows as locked, with the policy the locked rule gives.
- The same transaction sets the request's `completed_at`, whether the completion completed or was refused (a refusal at
  consumption or validation included), and reports the completion. A response no request matches marks nothing. A
  request whose application is no longer registered is marked completed by its consumption instead, in the same write
  as `consumed_at`, since that completion is rejected with no trusted target and never reaches the transaction.
- The lock order is `flows.md`'s: the tenant's enforcement row (when it applies), then the connection with the rule's
  connections in ascending id order, then its request's, then (in the stages) links and codes. A change that voids a
  connection's requests locks the connection first, so it waits for a completion that holds it, and finds its request
  finished; a completion that consumed a request before the change refuses it under the lock afterwards.
- An enforcement change waits for a completion that holds the rule's lock, and a completion that waited sees the rule
  as changed. The code carries the version checked; the redemption locks the rule again and rechecks it, and the
  session is written there. On PostgreSQL under `REPEATABLE READ`, a completion that waited may get a serialisation
  failure instead (SQLSTATE `40001`): it propagates as a server error, the locked transaction rolled back and its
  request left consumed but not completed.

### Outcomes

| How it ended                                                       | `CompletionResult`                                              |
|--------------------------------------------------------------------|-----------------------------------------------------------------|
| A full limit                                                       | `rateLimited($retryAfter)`                                      |
| A method, a connection or a protocol the endpoint does not take    | `rejected(request_unknown)`, `rejected(connection_unavailable)` |
| Refused before a request was consumed for a registered application | `rejected($reason)`                                             |
| Refused once a request was consumed for a registered application   | `failed($reason, $redirectUri, $delivery, $reference)`          |
| Every step ran                                                     | `completed($redirectUri, $delivery, $reference, $handoff)`      |

The redirect URI is `Applications\ApplicationGate::redirectUri($application, $connection)`, the exact URI the bound
`RedirectUriResolver` answers, checked; the delivery is the application's; the reference the request's.

### Events

`Completion\CompletionEvents::report($flow, $outcome)` reports each completion once, through the one projection and
`Events\AfterCommitDispatcher`:

- completed: `ResultVerified`, then `HandoffIssued`;
- refused once the response was verified: `ResultVerified`, then `FlowFailed($flow, $reason)`;
- refused before (the limit included): exactly one `FlowFailed`.

The context names the connection, its tenant and protocol once it was read; the application, the purpose and the
`request_reference` once the request was consumed; the identity (the linked one for `sign_in`, the request's for `link`
and `reauthenticate`) and the session of a `reauthenticate`. Never a subject, an attribute, the protocol state, a
nonce, a verifier, an assertion or a code. Inside the locked transaction the events wait for its commit; a refusal with
no target is dispatched at once.

## Success Path

1. The application's route calls `callback()` (or `assertionConsumerService()`) with the connection id and
   `CompletionRequest::fromRequest($request)`.
2. The attempt is counted, the method and the connection checked, and the driver correlates the response.
3. The request is consumed under the connection's lock, then the driver validates the response, and the result is
   built.
4. Under the tenant's enforcement lock (when it applies), the connections' and the request's: the link is resolved,
   enforcement is satisfied, the unlinked decision passes, the policy is asked again and the code issued; the request
   is marked completed.
5. Once that commits, `ResultVerified` and `HandoffIssued` are reported, and the helper answers `completed`, which the
   controller turns into a redirect with `Responses\CompletionResponses`.

## Failure / Edge Cases

- A replay of a completed or refused response finds its request consumed: `rejected(request_unknown)`.
- A response that names a request of another connection consumes it and fails with `connection_mismatch`, redirected
  to that request's application (SSO-5.5).
- A request at or past its expiry consumes it and fails with `request_expired`.
- A connection disabled after the start: the request is consumed, the driver is never asked, and the completion fails
  with `connection_unavailable`, redirected. Disabled while the driver validates: refused under the lock, after
  `ResultVerified`.
- A request voided while the driver validates: refused under the lock with `connection_unavailable`, and no code.
- Refreshed metadata that lapses while the driver validates: refused under the lock with `metadata_expired`, redirected,
  with nothing recorded and no code.
- An application whose policy no longer allows external sign-in at issuance: `application_not_allowed`, redirected.
- An application no longer registered when its request is consumed: `rejected(application_not_allowed)`, with no
  target. Its request is terminal at once: the consumption's own write sets `completed_at` with `consumed_at`, since
  no locked step runs for a completion with no trusted target to answer to.
- A database error, an issuer that throws, a stage that resolves to something else and a redirect URI resolver that
  answers what no redirect URI may be all propagate as server errors (SSO-11.4); inside the locked transaction they roll
  it back, so no code is kept, `completed_at` stays unset and nothing is reported, while the request stays consumed.
- A completion called inside a transaction open on the storage connection is a `LogicException` before it writes
  anything: no attempt is counted, no request consumed and nothing reported.

## Implementation Anchors

- `src/Completion/CompletionService.php`, `src/Completion/CompletionPipeline.php`, `src/Completion/ResultBuilder.php`,
  `src/Completion/CompletionEvents.php`.
- `src/Completion/Stages/CorrelateResponse.php`, `ConsumeRequest.php`, `ValidateResponse.php`, `ResolveLink.php`,
  `CheckEnforcement.php`, `DecideUnlinked.php`, `IssueHandoff.php`, and the shared `DomainReservation.php` and
  `Provisioning.php`.
- `src/Completion/CompletionState.php`, `src/Completion/StageOutcome.php`, `src/Completion/CompletionResult.php`,
  `src/Flows/RequestConsumption.php`.

## Authoritative Tests

- `tests/Feature/Completion/CompletionServiceTest.php`: every outcome and its exact result, the method and protocol of
  each endpoint, an unknown connection, a disabled connection, another connection's request, the expiry boundaries, a
  replay, unlinked handoffs off and on, enforcement satisfied, unsatisfied and its version, the policy turned off, the
  deadline limiting, ignored and absent, the grant field by field, the limits, a database error.
- `tests/Feature/Completion/CompletionEventSequenceTest.php`: each sequence and its whole context, and no secret.
- `tests/Feature/Completion/ResultBuilderTest.php`: the result, the mapping and its caps, every `emailDomainVerified`
  boundary.
- `tests/Feature/Completion/CompletionPipelineTest.php`: the stage of each step, the order, the transaction levels, the
  rows as locked, a refusal ending the pipeline, `completed_at`, a request voided and a connection disabled or gone
  under the lock, the lock order (enforcement, then connections in id order, then the request) and the locked policy
  carried to the enforcement step, no enforcement statement with the feature off or for a completion already refused,
  an enforcing tenant that moved, misconfigurations that propagate.
- `tests/Feature/Completion/Stages/StagesTest.php`: each stage alone.
- `tests/Integration/Completion/ConcurrentCompletionTest.php`: completions of one response, and a completion racing a
  change that voids its request while it validates, the change plain and inside its own transaction, on MySQL and
  PostgreSQL.
- `tests/Integration/Completion/CompletionTransactionTest.php`: a throwing issuer and a database error roll back with no
  event; a completion at either endpoint inside a caller's transaction is refused before it writes anything.
- `tests/Performance/CompletionQueryBudgetTest.php`: the reads and writes of each outcome.

## Change Triggers

- A step's stage changing what it goes on with or refuses with, or a new refusal before the steps.
- A change to which transaction a step runs in, to the locks it takes or their order.
- A change to what the verified result holds or how `emailDomainVerified` is judged.
- A change to the events a completion reports or to their context.
- Re-initiation of unsolicited SAML responses (P4), and domain reservation and provisioning (P6) replacing their seams.
