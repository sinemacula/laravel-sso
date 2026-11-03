# Event Model

## Purpose

This note records what a package event is: the context every one carries, the one projection that builds it and what
it refuses, when an event is dispatched, and how a refused operation is reported (SSO-10.2, SSO-10.4, SSO-10.5, SSO-9.6,
SSO-9.8). Audit sinks, SIEM forwarders and `laravel-audit-log` attach to these events, so their shape and their timing
are a contract.

## Invariants

- Every event the package dispatches implements `Contracts\SsoEvent` and carries one `Events\EventContext`
  (`context()` returns it), so one listener on the contract receives them all and attributes each the same way.
  Laravel dispatches an event to the listeners of the interfaces it implements, so no package event needs listing.
- `EventContext` is `final readonly` and holds strings only, fixed when it is built, under the names
  `laravel-authentication`'s events give the same facts (AUTH-9.4, SSO-9.6):

  | Field                                          | Meaning                                                                |
  |------------------------------------------------|------------------------------------------------------------------------|
  | `occurredAt`                                   | When the event was built, from `Contracts\Clock` (a `CarbonImmutable`) |
  | `ip`, `userAgent`                              | The client of the request being served                                 |
  | `connectionId`                                 | The connection the event concerns                                      |
  | `tenantId`                                     | The tenant the connection belongs to: an opaque string id              |
  | `protocol`                                     | `saml2`, `oidc`, or a registered driver's name                         |
  | `application`                                  | The configured application the flow is for                             |
  | `purpose`                                      | `sign_in`, `link` or `reauthenticate`                                  |
  | `requestReference`                             | The authorisation request's public reference: the only flow identifier |
  | `identityMorphClass`, `identityId`             | The identity reference, once the flow resolved one                     |
  | `actingIdentityMorphClass`, `actingIdentityId` | The identity acting, for administration, as the application passes it  |
  | `principalMorphClass`, `principalId`           | The session's principal, where one applies                             |
  | `activeTenantId`                               | The tenant a session is active in, where one applies                   |
  | `sessionId`                                    | The session, where one applies                                         |
  | `method`                                       | The sign-in method, where one applies                                  |

  `tenantId` and `activeTenantId` differ: the first is the tenant that owns the connection, the second the tenant a
  session acts within, which an identity in several tenants may switch. A part the flow did not establish, or that does
  not apply to the event, is `null`. `toArray()` is the record an audit sink keeps: snake_case keys, and `occurred_at`
  as an ISO 8601 UTC string to the microsecond.
- One projection builds every context: `Events\EventContexts::make()`. Nothing else in the package calls
  `new EventContext`. Its parameter list is the admission control: fifteen named fields, each `?string` defaulting to
  `null`, and nothing else. No array and no object is admitted, so a verified result, a request, a raw payload or a set
  of mapped attributes can never reach an event whole, and a field the context does not name cannot reach one. A
  secret, an assertion, a provider token, a verifier, a handoff code, protocol state (`state`, `RelayState`, a nonce,
  the PKCE verifier) and a transport header have no parameter to arrive through (SSO-10.4). Later parts of the package
  add typed convenience methods to the projection (from a verified result, from an authorisation request) that pick the
  fields they may and pass them to `make()`.
- The public reference (`requestReference`) is the only flow identifier an event carries (SSO-9.8). The authorisation
  request's internal id, its `state` and `RelayState`, the SAML request and assertion ids, and the handoff code are
  never passed to the projection.
- Mapped attributes appear only on the unlinked-result event (SSO-8.6), which carries them on its own fields, outside
  the context, because a provisioning listener needs them. No other event carries one.
- The projection reads the time from `Contracts\Clock` and the client from the container's `request`, resolved on each
  call and never held, so an Octane or queue worker never attributes one request's event to another's client
  (SSO-11.2). With no `request` bound, the client is `null`; in the console, it is what the request Laravel binds for
  the console reports.
- Every value is cleaned before it is kept, without reading configuration:
  - the IP address is kept only when it is a valid IPv4 or IPv6 address;
  - the user agent has invalid UTF-8 replaced (`mb_scrub`), C0 controls, DEL, C1 controls and the Unicode
    bidirectional controls (U+202A to U+202E, U+2066 to U+2069) removed, and is cut to 512 characters
    (`EventContexts::USER_AGENT_MAX_LENGTH`);
  - every named field is cleaned the same way and cut to 255 characters (`EventContexts::FIELD_MAX_LENGTH`), so an id
    can never smuggle a payload, forge a log line or reorder text in an audit view;
  - a value that is empty once cleaned is `null`.
- Events report only. Nothing that must happen for security depends on a listener: enforcement is a synchronous
  contract call (SSO-4.5, SSO-4.6), never a listener (SSO-10.5).
- Every event but the unlinked-result event is dispatched through `Events\AfterCommitDispatcher::dispatch()`, once the
  writes that caused it commit, on the storage connection unless the caller names another:
  - with no transaction open on that connection, at once;
  - otherwise on the commit of the innermost transaction open on it whose callbacks apply
    (`DatabaseTransactionsManager::callbackApplicableTransactions()`), and never when that transaction, or a savepoint
    it sits in, rolls back;
  - a transaction open on another connection neither delays nor cancels it, since the writes were not made in it;
  - never when the commit of the outermost transaction it waits in fails, then or later.

  No package event implements `ShouldDispatchAfterCommit`, which would wait for the last transaction of any connection.
  The events dispatcher, the transactions manager and the database manager are resolved on each call, never held.
- Laravel 12 does not tell its transactions manager when an outermost commit fails
  (`ManagesTransactions::handleCommitTransactionException()`), so the callbacks waiting on that transaction stay pending
  and run on the next outermost commit on the connection, which on a long-running worker can be another request's.
  Laravel 13 drops them. The package does not rely on either: `Events\TransactionGenerations` counts each outermost
  transaction begun on a connection, from a `TransactionBeginning` listener the service provider registers once, and a
  savepoint never counts. Each callback carries its connection's generation when it was queued, and dispatches nothing
  once that has moved on: a transaction that commits runs its callbacks before the next one begins, so only a failed
  commit leaves one to run under a later generation. A record such a transaction left is found only while the
  connection has a transaction open, so an event dispatched outside one is still dispatched at once. This covers the
  application's own outermost transaction on the storage connection as well as the package's.
- `TransactionGenerations` is a singleton, resolved when the provider boots, never scoped: a late callback can run in a
  later request or job than the one that queued it, and a count started afresh there could reach the generation it was
  queued in again. It holds a count by connection name and nothing of a request (SSO-11.2).
- The unlinked-result event (SSO-8.6) alone is dispatched with `dispatchNow()`: synchronously, inside the flow,
  before any handoff is issued, so a listener can provision the identity in time. A queued listener on it is too late.
- One failure event, `Events\FlowFailed`, reports every refused operation, with the flow (`Events\Enums\Flow`) and the
  reason (`Events\Enums\FailureReason`), and exactly one is fired per refused operation, however many checks it failed
  (SSO-10.2). It holds its context, its flow and its reason and nothing else: no free-text message, since a provider's
  diagnostic text goes to the logs, sanitised.

  | Flow                    | The operation refused                                               |
  |-------------------------|---------------------------------------------------------------------|
  | `authorization_request` | Starting a flow, discovery by email domain included                 |
  | `assertion`             | A SAML response at the assertion consumer service, solicited or not |
  | `callback`              | An OIDC authorisation response                                      |
  | `redemption`            | A handoff code presented for redemption                             |

- `FlowFailed` crosses a queue as it is: its context is strings and a `CarbonImmutable`, its flow and reason are enums,
  so a queued listener receives what a synchronous one does.
- `FailureReason` and `Flow` are stable once released: a value is never renamed or reused, and a removed one leaves its
  value unused. A part of the package that reports a new reason adds its case to `FailureReason`, in the group of its
  flow; SIEM consumers count by these values.
- Administration events (SSO-10.3) report each change a management helper makes to a connection, a key or a certificate,
  and the nearing expiry of a key or certificate. `Administration\AdministrationEvents` builds every one, its context
  through `EventContexts::make()` from the connection's id, its tenant and protocol and the acting identity the
  application passed (`Administration\ActingIdentity`, as `actingIdentityMorphClass` and `actingIdentityId`), and hands
  it to `AfterCommitDispatcher::dispatch()` inside the helper's transaction, so it is delivered when that transaction
  commits and never when it, or a transaction the application wrapped it in, rolls back (SSO-10.5). Its context carries
  no flow identifier, identity, application or purpose. A refused change and a change that changed nothing report
  nothing, and fire no `FlowFailed`, since a helper's refusal is its result. No administration event holds a secret, a
  ciphertext, a private key or a setting's value: `ConnectionUpdated` names what changed, never its value. The
  nearing-expiry event reports a certificate's end of validity and never enforces it, with no acting identity.
  `administration-events.md` records the rest:

  | Event                | Fields beyond the context                                  | Dispatched by                                                  |
  |----------------------|------------------------------------------------------------|----------------------------------------------------------------|
  | `ConnectionCreated`  | none                                                       | `ConnectionService::create()`                                  |
  | `ConnectionUpdated`  | `changedSettings`, names only                              | `ConnectionService::update()`, `SubjectMigration::migrate()`   |
  | `ConnectionEnabled`  | none                                                       | `ConnectionService::enable()`, when it was disabled            |
  | `ConnectionDisabled` | none                                                       | `ConnectionLifecycle::disable()`, when it was enabled          |
  | `ConnectionDeleted`  | none                                                       | `ConnectionLifecycle::delete()`                                |
  | `KeyAdded`           | `keyId`, `use`, `state`, `fingerprint`, `notAfter`         | `KeyService::addNext()`, `trustCertificate()`                  |
  | `KeyMadeCurrent`     | `keyId`, `use`, `fingerprint`, `previousKeyId`             | `KeyService::addNext()` for a use's first key, `makeCurrent()` |
  | `KeyRetired`         | `keyId`, `use`, `fingerprint`                              | `KeyService::retire()`, `distrustCertificate()`                |
  | `KeyNearingExpiry`   | `keyId`, `use`, `fingerprint`, `notAfter`, `thresholdDays` | `Keys\ExpiryNotifier::notify()`                                |

## Success Path

1. A flow works inside the transaction it opens on the storage connection.
2. It builds the context with `EventContexts::make()`, naming the connection, its tenant and protocol, the application,
   the purpose, the public reference and whatever else it has established.
3. It hands the event to `AfterCommitDispatcher::dispatch()`, which attaches it to the transaction's commit.
4. The transaction commits, and the event reaches every listener on its class and on `SsoEvent`; a queued listener
   receives it through the queue.
5. A refused operation does the same with one `FlowFailed`, after its own commit or at once when it wrote nothing.

## Failure / Edge Cases

- A transaction that rolls back drops every event dispatched in it; a savepoint that rolls back drops only the events
  dispatched inside it, while those of the outer transaction still follow its commit.
- Under the transactions manager of Laravel's testing traits, the transaction wrapping each test never commits, so it
  does not defer an event; one opened inside it does.
- With no transactions manager bound, nothing can be deferred and the event is dispatched at once.
- A commit that fails drops the events waiting on it, those of a savepoint that committed inside it included, on Laravel
  12 as on Laravel 13; the next transaction to commit on the connection delivers its own events alone.
- A connection whose events dispatcher does not deliver `TransactionBeginning` keeps its count, and a callback a failed
  commit left on it runs as Laravel 12 runs it.
- A malformed `sso.storage.connection` fails closed with `StorageConnection`'s `InvalidArgumentException` before any
  event is dispatched; a database error propagates.
- A listener's exception propagates as it does from Laravel's dispatcher: from the dispatch, or from the commit that ran
  it, after the write is committed.
- A dispatcher swapped in between the write and its commit (`Event::fake()`) receives the event, since it is resolved
  when the event is dispatched.
- A user agent with control or bidirectional characters, invalid UTF-8 or more than 512 characters is cleaned, never
  refused; a field over 255 characters is cut. An IP address that is not one is `null`.

## Implementation Anchors

- `src/Contracts/SsoEvent.php`, `src/Events/EventContext.php` (`toArray()`).
- `src/Events/EventContexts.php`: `make()`, the cleaning and the caps.
- `src/Events/AfterCommitDispatcher.php`: `dispatch()`, `dispatchNow()`, `pendingTransaction()`,
  `hasOpenTransaction()`.
- `src/Events/TransactionGenerations.php`: `begun()`, `current()`; `src/SsoServiceProvider.php`:
  `countOutermostTransactions()`.
- `src/Events/FlowFailed.php`, `src/Events/Enums/Flow.php`, `src/Events/Enums/FailureReason.php`.
- `src/Database/StorageConnection.php`: `resolvedName()`, the default connection of the dispatch.
- `tests/Concerns/RecordsEventSequences.php`: the event sequence harness. A flow test records with
  `startRecordingEvents()` and asserts `assertExactlyOneFailure($flow, $reason)` for every refused start, completion,
  callback and redemption, `assertNoFailure()` for an accepted one, `assertEventSequence()` for the order of what was
  reported, and `assertNoEvents()` where nothing may be.
- `src/Administration/AdministrationEvents.php`, `src/Administration/ActingIdentity.php`: the administration events'
  context and dispatch.
- `src/Events/ConnectionCreated.php`, `ConnectionUpdated.php`, `ConnectionEnabled.php`, `ConnectionDisabled.php`,
  `ConnectionDeleted.php`, `KeyAdded.php`, `KeyMadeCurrent.php`, `KeyRetired.php`, `KeyNearingExpiry.php`.
- `src/Keys/ExpiryReport.php` and `src/Keys/ExpiryNotifier.php`: the nearing-expiry report and its warnings.

## Authoritative Tests

- `tests/Unit/Events/EventContextTest.php`.
- `tests/Unit/Events/FlowFailedTest.php`
  `testItIsAPackageEventReturningItsContext`, `testItSurvivesASerializeRoundTrip`,
  `testItHoldsNothingBeyondItsContextFlowAndReason`.
- `tests/Unit/Events/Enums/FlowTest.php`, `tests/Unit/Events/Enums/FailureReasonTest.php`.
- `tests/Feature/Events/EventContextsTest.php`
  `testTheTimeComesFromTheBoundClock`, `testTheClientComesFromTheRequestCleanedAndCapped`,
  `testTheConsoleGivesTheRequestsOwnAddress`, `testNoRequestBoundGivesNoClient`,
  `testEveryNamedFieldReachesTheContext`, `testEachFieldIsCleanedAndCapped`, `testTheRequestIsResolvedOnEachCall`,
  `testTheProjectionAdmitsTheContextsStringFieldsOnly`.
- `tests/Feature/Events/AfterCommitDispatcherTest.php`
  `testDispatchesAtOnceOutsideATransaction`, `testWaitsForTheStorageConnectionsTransactionToCommit`,
  `testNeverDispatchesAfterARollback`, `testARolledBackSavepointDropsOnlyItsEvents`,
  `testATransactionOnAnotherConnectionDoesNotDefer`, `testTheDefaultConnectionFollowsTheStorageConnection`,
  `testDispatchNowIsImmediateInsideATransaction`, `testIgnoresTheTransactionWrappingATest`,
  `testNestedSavepointRollbacksDropOnlyTheirEvents`, `testACallbackLeftByAFailedCommitIsDropped`,
  `testDispatchesAtOnceBesideARecordAFailedCommitLeft`.
- `tests/Feature/Events/TransactionGenerationsTest.php`
  `testAConnectionStartsAtNought`, `testEachOutermostBeginAdvancesTheGenerationByOne`,
  `testASavepointDoesNotAdvanceTheGeneration`, `testTheGenerationIsPerConnection`, `testOneCountServesTheProcess`.
- `tests/Feature/Events/RecordsEventSequencesTest.php`.
- `tests/Integration/Events/AfterCommitDispatchTest.php`
  `testAnEventIsDeliveredWhenItsWriteCommits`, `testAnEventIsDroppedWhenItsWriteRollsBack`,
  `testAChangeWhoseCommitFailsIsNeverReported`, `testTheApplicationsFailedCommitTakesThePackagesEventsWithIt`,
  `testAQueuedListenerReceivesTheFailureIntact`.
- `tests/Unit/Events/AdministrationEventClassesTest.php`
  `testEachIsAPackageEventReturningItsContext`, `testEachSurvivesASerializeRoundTrip`,
  `testEachHoldsExactlyItsDeclaredProperties`, `testConnectionUpdatedHoldsAListOfNamesOnly`.
- `tests/Feature/Administration/AdministrationEventsTest.php`.
- `tests/Feature/Administration/AdministrationEventSequenceTest.php`
  `testAnUpdateNamesExactlyWhatChangedInOrder`, `testAddingKeysReportsAddedThenMadeCurrent`,
  `testARefusalReportsNothing`.
- `tests/Feature/Keys/ExpiryReportTest.php`
  `testReportsEachRowOnceWithNoActingIdentity`.
- `tests/Integration/Administration/AdministrationEventsAfterCommitTest.php`
  `testAnOperationRolledBackWritesAndReportsNothing`, `testAnOperationCommittedReportsOnlyAfterTheCommit`,
  `testAQueuedListenerReceivesTheUpdateIntact`.
- `tests/Integration/Administration/NoSecretInAdministrationEventsTest.php`
  `testNoEventHoldsASecretOrASettingValue`.

## Change Triggers

Update this note when any of the following change:

- the fields of `EventContext`, their names, or what the projection admits, cleans or caps
- an event that stops implementing `SsoEvent`, or a new package event
- the after-commit dispatch, its default connection, or an event that is dispatched synchronously
- how Laravel's transactions manager treats a failed commit, or how outermost transactions are counted
- the failure event, its flows, or the rule of one failure event per refused operation
- a `FailureReason` or `Flow` value
