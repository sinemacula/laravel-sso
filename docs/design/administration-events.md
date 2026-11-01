# Administration Events

## Purpose

This note records the events a change to a connection, a key or a certificate reports (SSO-10.3): what each carries and
what it never carries (SSO-10.4), who dispatches each and when, after the change commits and never when it rolls back
(SSO-10.5), and the nearing-expiry report, which reports a certificate's end of validity and never enforces it (SSO-2.6,
SSO-11.12). Audit trails attach to these events to record who changed an identity provider's trust, so their shape and
their timing are a contract. The domain, enforcement, metadata and link events arrive with their parts of the package
and follow the same rules.

## Invariants

- There are nine administration events, in `src/Events`. Each is `final readonly`, implements `Contracts\SsoEvent`,
  holds one `Events\EventContext` as `$context` (`context()` returns it) and the public fields below, and nothing else:

  | Event                | Fields beyond the context                          | Reports                                          |
  |----------------------|----------------------------------------------------|--------------------------------------------------|
  | `ConnectionCreated`  | none                                               | A connection created, disabled                   |
  | `ConnectionUpdated`  | `changedSettings`                                  | Its settings, secrets, name or mapping changed   |
  | `ConnectionEnabled`  | none                                               | A connection enabled                             |
  | `ConnectionDisabled` | none                                               | A connection disabled                            |
  | `ConnectionDeleted`  | none                                               | A connection deleted                             |
  | `KeyAdded`           | `keyId`, `use`, `state`, `fingerprint`, `notAfter` | A key pair generated, or a certificate trusted   |
  | `KeyMadeCurrent`     | `keyId`, `use`, `fingerprint`, `previousKeyId`     | A key of the service provider's own made current |
  | `KeyRetired`         | `keyId`, `use`, `fingerprint`                      | A key retired, or a certificate distrusted       |
  | `KeyNearingExpiry`   | `keyId`, `use`, `fingerprint`, `notAfter`          | A validity ending within the warning, or ended   |

  `changedSettings` is a `list<string>` of names, each once. `keyId` is the row's ULID; `use` a `Keys\Enums\KeyUse`;
  `state` a `Keys\Enums\KeyState` (`current` or `next` for a key added, `null` for a trusted certificate); `fingerprint`
  the lower-case hex SHA-256 of the certificate's DER, the public identifier an administrator compares; `notAfter` a
  `CarbonImmutable` in UTC, `null` on `KeyAdded` for a row with no certificate; `previousKeyId` the key replaced, now
  `retiring`, or `null` when there was none.
- Every event is built by `Administration\AdministrationEvents`, one method per event, and its context through the one
  projection, `Events\EventContexts::make()` (see `event-model.md`), from four facts only: the connection's id, its
  tenant (`tenantId`), its protocol (`saml2`, `oidc` or a registered driver's name), and the acting identity as the
  application passed it (`actingIdentityMorphClass`, `actingIdentityId`). The time comes from `Contracts\Clock` and the
  client (`ip`, `userAgent`) from the request being served. Every other field of the context is `null`: an
  administration change has no flow, so no `requestReference`, `application` or `purpose`, and no identity, principal,
  session or method.
- The acting identity is an `Administration\ActingIdentity`: a type and an id, each a non-empty opaque string (under
  `laravel-iam`, the identity's morph class and key, as `laravel-authentication`'s events give them). Each helper takes
  it as an optional last argument; without one, the context's acting identity is `null`. Who may manage a connection is
  the application's authorisation, never the package's: the event reports who did.
- Who dispatches each event, and when:

  | Event                | Dispatched by                                               | When                                                                        |
  |----------------------|-------------------------------------------------------------|-----------------------------------------------------------------------------|
  | `ConnectionCreated`  | `ConnectionService::create()`                               | Once the connection is inserted                                             |
  | `ConnectionUpdated`  | `ConnectionService::update()`                               | Once the change is saved, when something changed                            |
  | `ConnectionEnabled`  | `ConnectionService::enable()`                               | Once a disabled connection is enabled                                       |
  | `ConnectionDisabled` | the disabling helper (BL-37)                                | No helper dispatches it yet                                                 |
  | `ConnectionDeleted`  | the deleting helper (BL-37)                                 | No helper dispatches it yet; it is reported with the connection read before |
  | `KeyAdded`           | `KeyService::addNext()`, `KeyService::trustCertificate()`   | Once the key or certificate is inserted                                     |
  | `KeyMadeCurrent`     | `KeyService::addNext()`, `KeyService::makeCurrent()`        | After `KeyAdded` for a use's first key; once a `next` key is promoted       |
  | `KeyRetired`         | `KeyService::retire()`, `KeyService::distrustCertificate()` | Once the row is deleted, reported as it was read before                     |
  | `KeyNearingExpiry`   | `Keys\ExpiryReport::report()`                               | For each row reported, with no acting identity                              |

- `ConnectionUpdated` names what changed in one order: the settings as the protocol's setting enum lists them
  (`Saml2Setting`, `OidcSetting`; a registered driver's in the order its settings hold them), then the secrets, then
  `display_name`, then `attribute_mapping`. A secret is named (`client_secret`) when it was set, replaced or cleared,
  never by its value before or after; a setting is named when its stored value or its presence changed.
- Sequences: creating a connection reports `[ConnectionCreated]`; an update `[ConnectionUpdated]`; enabling
  `[ConnectionEnabled]`; the first `addNext()` of a use `[KeyAdded (current), KeyMadeCurrent (previousKeyId null)]`, and
  a later one `[KeyAdded (next)]`; `makeCurrent()` `[KeyMadeCurrent]` naming the key replaced; `retire()` and
  `distrustCertificate()` `[KeyRetired]`; `trustCertificate()` `[KeyAdded]` with the use `idp_signing` and no state.
- After commit only. Each helper writes in one transaction on the storage connection and calls the reporter inside it,
  after the write; the reporter hands each event to `Events\AfterCommitDispatcher::dispatch()`, which delivers it when
  the transaction commits and drops it when it rolls back. A helper called inside a transaction the application opened
  on the storage connection reports nothing until that transaction commits, and nothing at all when it rolls back,
  though the helper returned success; a transaction on another connection neither delays nor withdraws the event.
- No event for a refusal or a no-op. A refusal (`freshness_required`, `connection_not_found`, `key_not_found`,
  `settings_invalid`, `protocol_unavailable`, `key_state_conflict`) writes nothing and reports nothing: no
  administration event, and no `FlowFailed`, which reports refused flows, not refused administration; the refusal is the
  helper's result. A change that changes nothing (an update giving what is stored, enabling an enabled connection)
  succeeds as `unchanged` and reports nothing. `connectionUpdated()` itself reports nothing for an empty list of names,
  and each name once.
- No secret. The events hold ids, enum cases, a fingerprint, times and names. None holds a secret, a ciphertext, a
  private key, a PEM, a setting's value or the settings: no property is named `secret`, `private_key`, `value` or
  `settings`, and `ConnectionUpdated` holds names only. Every field is a string, an enum, a `CarbonImmutable` or a list
  of strings, so an event crosses a queue as it is and a queued listener receives what a synchronous one does.
- Every change asks the freshness contract before it writes (SSO-2.12, see `freshness.md`), so a stale caller is refused
  before anything could be reported:

  | Change                                                  | Operations asked                                                       |
  |---------------------------------------------------------|------------------------------------------------------------------------|
  | `create()`                                              | `sso.connection.trust`, and each other operation a setting given needs |
  | `update()` of a trust setting or a secret               | `sso.connection.trust`                                                 |
  | `update()` of IdP-initiated sign-in or its start URL    | `sso.connection.idp_initiated`                                         |
  | `update()` of the name, the mapping or the scopes alone | nothing                                                                |
  | `enable()`                                              | `sso.connection.enable`, even when the connection is enabled already   |
  | `addNext()`, `makeCurrent()`, `retire()`                | `sso.keys.rotate`                                                      |
  | `trustCertificate()`, `distrustCertificate()`           | `sso.connection.trust`                                                 |

  Each is asked with the maximum age configured for it under `sso.freshness.max_age_seconds`.
- Nearing expiry is reported, never enforced. `Keys\ExpiryReport::report(?int $withinDays = null)` reads every key and
  certificate of any connection whose `not_after` is set and at or before the clock's now plus the window, on the write
  connection, ordered by `not_after` and then by id. The window is `sso.keys.expiry_warning_days` (30 by default) unless
  a number of days from 1 to 365 is given, each day 86400 seconds. A row already expired is included; a row with no
  `not_after` never is; a `retiring` key whose `retiring_until` is at or before now is left out, since decryption no
  longer accepts it. The rows' connections are loaded on the write connection in one query, and a row whose connection
  is gone is skipped. Each row is reported with one `KeyNearingExpiry` through `keyNearingExpiry()` with no acting
  identity, at once outside a transaction, and returned as a `Keys\KeySummary`. The report writes nothing and changes
  nothing: an expired certificate is still trusted, and no key is withdrawn. The scheduled command `sso:keys:expiring`,
  and the de-duplication that keeps it from reporting a key on every run, arrive with BL-70.

## Success Path

1. The application's administration screen authorises its user, then calls a helper with the tenant, the connection and
   an `ActingIdentity` for that user.
2. The helper finds the connection, validates what it was given and asks the freshness contract.
3. In one transaction on the storage connection it writes, then calls `AdministrationEvents`, which builds the event's
   context from the connection and the acting identity and hands the event to the after-commit dispatcher.
4. The transaction commits, and the event reaches every listener on its class and on `SsoEvent`; an audit trail records
   `$event->context()->toArray()` with the event's own fields, and a queued listener receives it through the queue.
5. On a schedule, the application calls `ExpiryReport::report()`; each key or certificate nearing its end of validity is
   reported, and an alerting listener tells an administrator to rotate it.

## Failure / Edge Cases

- A refused change returns its reason and reports nothing; the audit trail of refusals, if the application wants one, is
  the application's, from the result.
- A helper that succeeded inside the application's own transaction on the storage connection, which then rolled back,
  reported nothing: listeners never record a change that did not happen.
- Enabling an enabled connection asks for freshness and reports nothing; an update giving the stored values asks nothing
  and reports nothing.
- The first key of a use is reported twice, `KeyAdded` then `KeyMadeCurrent`, in that order, in the same commit.
- `KeyRetired` names a row that no longer exists: it is reported with the row as read before the delete.
- `ConnectionDisabled` and `ConnectionDeleted` exist and are reported by `AdministrationEvents`, but no helper calls
  them until the disabling and deleting helpers arrive (BL-37).
- An `ActingIdentity` with an empty type or id is the application's mistake: an `InvalidArgumentException` before any
  helper runs.
- `ExpiryReport::report()` given 0, a negative number or more than 365 days throws an `InvalidArgumentException`,
  `An expiry report looks 1 to 365 days ahead.`, before anything is read; a malformed `sso.keys.expiry_warning_days`
  fails closed with `KeySettings`' exception naming the key. Called twice, it reports the same rows twice.
- A listener's exception propagates as Laravel's dispatcher propagates it, after the change has committed.

## Implementation Anchors

- `src/Administration/AdministrationEvents.php`, `src/Administration/ActingIdentity.php`.
- `src/Events/ConnectionCreated.php`, `ConnectionUpdated.php`, `ConnectionEnabled.php`, `ConnectionDisabled.php`,
  `ConnectionDeleted.php`, `KeyAdded.php`, `KeyMadeCurrent.php`, `KeyRetired.php`, `KeyNearingExpiry.php`.
- `src/Events/EventContexts.php`, `src/Events/AfterCommitDispatcher.php`: the projection and the dispatch.
- `src/Connections/ConnectionService.php`: `create()`, `update()` (`applyChanges()`, `changedSettings()`), `enable()`.
- `src/Keys/KeyService.php`: `insertOwnKey()`, `insertTrusted()`, `promote()`, `remove()`.
- `src/Keys/ExpiryReport.php`: `report()`; `src/Keys/KeySettings.php`: `expiryWarningDays()`.
- `src/Freshness/FreshnessGate.php`, `src/Testing/FakeFreshness.php`.

## Authoritative Tests

- `tests/Unit/Events/AdministrationEventClassesTest.php`
  `testEachIsAPackageEventReturningItsContext`, `testEachSurvivesASerializeRoundTrip`,
  `testEachHoldsExactlyItsDeclaredProperties`, `testConnectionUpdatedHoldsAListOfNamesOnly`.
- `tests/Feature/Administration/AdministrationEventsTest.php`
  `testReportsEachConnectionChange`, `testAnUpdateThatChangedNothingReportsNothing`, `testReportsEachKeyChange`,
  `testAKeyWithNoEndOfValidityIsNeverNearingExpiry`, `testReportsOnlyOnceTheChangeCommits`,
  `testAnActingIdentityNeedsATypeAndAnId`.
- `tests/Feature/Administration/AdministrationEventSequenceTest.php`
  `testCreatingReportsConnectionCreated`, `testAnUpdateNamesExactlyWhatChangedInOrder`,
  `testAnUpdateOfOneSettingNamesItAlone`, `testAnUpdateChangingNothingReportsNothing`,
  `testEnablingReportsOnceAndNeverAgain`, `testAddingKeysReportsAddedThenMadeCurrent`,
  `testMakingCurrentAndRetiringReportEachChange`, `testTrustingAndDistrustingACertificateReportEachChange`,
  `testARegisteredProtocolIsReportedByItsName`, `testARefusalReportsNothing`.
- `tests/Feature/Administration/FreshnessConventionTest.php`
  `testTheDefaultContractRefusesWithNothingWritten`, `testAFreshCallerIsAskedExactlyItsOperations`,
  `testAChangeThatWidensNothingAsksNothing`, `testEnablingAsksEvenWhenAlreadyEnabled`.
- `tests/Feature/Keys/ExpiryReportTest.php`
  `testTheDefaultWindowIsThirtyDays`, `testTheConfiguredWarningSetsTheWindow`,
  `testAGivenWindowReplacesTheConfiguredOne`, `testExpiredRowsAreIncluded`, `testARetiringKeyPastItsOverlapIsExcluded`,
  `testAKeyWithNoEndOfValidityIsNeverReported`, `testOrdersByEndOfValidityThenId`,
  `testReportsEachRowOnceWithNoActingIdentity`, `testSkipsARowWhoseConnectionIsGone`, `testChangesNothing`,
  `testReadsTheWriteConnection`, `testRefusesADayCountOutOfRange`, `testAcceptsTheEdgesOfTheRange`.
- `tests/Integration/Administration/AdministrationEventsAfterCommitTest.php`
  `testAnOperationRolledBackWritesAndReportsNothing`, `testAnOperationCommittedReportsOnlyAfterTheCommit`,
  `testATransactionOnAnotherConnectionDefersNothing`, `testAQueuedListenerReceivesTheUpdateIntact`.
- `tests/Integration/Administration/NoSecretInAdministrationEventsTest.php`
  `testNoEventHoldsASecretOrASettingValue`.

## Change Triggers

Update this note when any of the following change:

- an administration event, its fields, or what its context carries
- the helper that dispatches an event, or the order of a helper's events
- the order or the names `ConnectionUpdated` gives
- whether a refusal or a no-op reports anything
- the after-commit dispatch of administration events
- the operations a change asks the freshness contract about
- the nearing-expiry report's window, what it includes or leaves out, or anything it writes or enforces
