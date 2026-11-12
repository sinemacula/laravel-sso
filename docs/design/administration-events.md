# Administration Events

## Purpose

This note records the events a change to a connection, a key or a certificate reports (SSO-10.3): what each carries and
what it never carries (SSO-10.4), who dispatches each and when, after the change commits and never when it rolls back
(SSO-10.5), and the nearing-expiry report, which reports a certificate's end of validity and never enforces it (SSO-2.6,
SSO-11.12). Audit trails attach to these events to record who changed an identity provider's trust, so their shape and
their timing are a contract. The domain and enforcement events follow the same rules and are listed under "Domain and
enforcement events" below; the metadata, JWKS and link events are in `metadata-refresh.md`, `oidc-discovery.md` and
`linking.md`.

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
  | `KeyNearingExpiry`   | those of `KeyRetired`, `notAfter`, `thresholdDays` | A validity ending within the warning, or ended   |

  `changedSettings` is a `list<string>` of names, each once. `keyId` is the row's ULID; `use` a `Keys\Enums\KeyUse`;
  `state` a `Keys\Enums\KeyState` (`current` or `next` for a key added, `null` for a trusted certificate); `fingerprint`
  the lower-case hex SHA-256 of the certificate's DER, the public identifier an administrator compares; `notAfter` a
  `CarbonImmutable` in UTC, `null` on `KeyAdded` for a row with no certificate; `previousKeyId` the key replaced, now
  `retiring`, or `null` when there was none; `thresholdDays` the most urgent threshold reached, 0 once the validity has
  ended.
- Every event is built by `Administration\AdministrationEvents`, one method per event, and its context through the one
  projection, `Events\EventContexts::make()` (see `event-model.md`), from four facts only: the connection's id, its
  tenant (`connectionTenantId`), its protocol (`saml2`, `oidc` or a registered driver's name), and the acting identity:
  the identity of the caller the application passed (`actingIdentityMorphClass`, `actingIdentityId`). The time comes
  from `Contracts\Clock` and the client (`ip`, `userAgent`) from the `Http\ClientContext` the helper was given: each
  change takes one, after its required values, and a console command passes `new ClientContext(null, null)`. Every other
  field of the context is `null`: an administration change has no flow, so no `requestReference`, `application` or
  `purpose`, and no identity, principal, session or method.
- The acting identity is the identity of the change's caller, an `Identities\Caller`: an `IdentityReference`, a type
  and an id, each 1 to 255 bytes (under `laravel-iam`, the identity's morph class and key, as
  `laravel-authentication`'s events give them), and the session it is on, which the freshness contract judges and no
  event carries. Each helper takes the caller as an optional argument after the client, and gives the same caller to
  freshness and to the event; without one, freshness is asked for no caller and the context's acting identity is
  `null`. Who may manage a connection is the application's authorisation, never the package's: the event reports who
  did.
- Who dispatches each event, and when:

  | Event                | Dispatched by                                                | When                                                                    |
  |----------------------|--------------------------------------------------------------|-------------------------------------------------------------------------|
  | `ConnectionCreated`  | `ConnectionService::create()`                                | Once the connection is inserted                                         |
  | `ConnectionUpdated`  | `ConnectionService::update()`, `SubjectMigration::migrate()` | Once the change is saved, when something changed                        |
  | `ConnectionEnabled`  | `ConnectionService::enable()`                                | Once a disabled connection is enabled                                   |
  | `ConnectionDisabled` | `ConnectionLifecycle::disable()`                             | Once an enabled connection is disabled and its flows voided             |
  | `ConnectionDeleted`  | `ConnectionLifecycle::delete()`                              | Once the connection and its rows are deleted, reported as locked before |
  | `KeyAdded`           | `KeyService::addNext()`, `KeyService::trustCertificate()`    | Once the key or certificate is inserted                                 |
  | `KeyMadeCurrent`     | `KeyService::addNext()`, `KeyService::makeCurrent()`         | After `KeyAdded` for a use's first key; once a `next` key is promoted   |
  | `KeyRetired`         | `KeyService::retire()`, `KeyService::distrustCertificate()`  | Once the row is deleted, reported as it was read before                 |
  | `KeyNearingExpiry`   | `Keys\ExpiryNotifier::notify()`                              | For each warning sent, with no acting identity                          |

  `ConnectionUpdated` is also reported by `LinkingPolicyService`, `EvidenceSettingsService`, `ImportSaver`,
  `MetadataApplier` and `OidcMetadataSource` when they change a connection.

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
  `settings`, and `ConnectionUpdated` holds names only. Every field is a string, an integer, an enum, a
  `CarbonImmutable` or a list of strings, so an event crosses a queue as it is and a queued listener receives what a
  synchronous one does.
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
- Nearing expiry is reported, never enforced.
  `Keys\ExpiryReport::report(ClientContext $client, ?int $withinDays = null, ?Closure $each = null)` lists every key and
  certificate of any connection whose `not_after` is set and at or before the clock's now plus the window, on the write
  connection, in pages by keyset on `not_after` and then id. The window is the largest of `sso.keys.expiry_thresholds`
  (30 by default) unless a number of days from 1 to 365 is given, each day 86400 seconds. A row already expired is
  included; a row with no `not_after` never is; a `retiring` key whose `retiring_until` is at or before now is left out,
  since decryption no longer accepts it. Each page's connections are loaded on the write connection in one query, and a
  row whose connection is gone is skipped. Each key that has reached a threshold, and was not warned of it or a more
  urgent one, is reported with one `KeyNearingExpiry` through `keyNearingExpiry()` with no acting identity, outside any
  transaction and at least once: see `operations.md`, with the command `sso:keys:expiring` and what the claim and the
  marker do. An expired certificate is still trusted, and no key is withdrawn.

### Domain and enforcement events

- Eight more events, in `src/Events`, each `final readonly`, implementing `Contracts\SsoEvent` with its context first:

  | Event                 | Fields beyond the context                                | Reported by                                                   |
  |-----------------------|----------------------------------------------------------|---------------------------------------------------------------|
  | `DomainClaimed`       | `domainId`, `domain`, `recordName`, `pendingExpiresAt`   | `DomainEvents::claimed()`, from `DomainService::claim()`      |
  | `DomainVerified`      | `domainId`, `domain`, `verifiedAt`                       | `DomainEvents::verified()`, from `DomainService::verify()`    |
  | `DomainRemoved`       | `domainId`, `domain`, `state`                            | `DomainEvents::removed()`, from `DomainService::remove()`     |
  | `DomainRecheckFailed` | `domainId`, `domain`, `failure`, `lapsesAt`              | `DomainEvents::recheckFailed()`, from the scheduled recheck   |
  | `DomainRestored`      | `domainId`, `domain`, `verifiedAt`, `checkedAt`          | `DomainEvents::restored()`, from the scheduled recheck        |
  | `DomainLapsed`        | `domainId`, `domain`                                     | `DomainEvents::lapsed()`, from the scheduled recheck          |
  | `EnforcementChanged`  | `enabled`, `connectionIds`, `version`, `previousVersion` | `EnforcementEvents::changed()`, from the enforcement helper   |
  | `ExemptionUsed`       | `enforcementVersion`                                     | `EnforcementEvents::exemptionUsed()`, from the exemption gate |

- A domain event's context names the connection that claimed the domain, its tenant and protocol, and the acting
  identity for a change a helper made; a recheck's has none. An enforcement change's context names the tenant whose
  rule changed (`connectionTenantId`) and the acting identity, and no connection. An exemption's names the enforcing
  tenant (`connectionTenantId`), the active tenant the session acts in (`tenantId`), the application, the identity and
  the session when the caller passed one.
- No domain event carries the verification token or a DNS record's value; `failure` is a
  `Domains\Enums\RecheckFailure`, `state` a `Domains\Enums\DomainState`, and every time a `CarbonImmutable` in UTC.
  `EnforcementChanged::$connectionIds` is a list of ids, each once, in id order.
- Each is handed to `Events\AfterCommitDispatcher` inside the transaction that made the change, after the write (and,
  for an enforcement change, after the revocation it needed), so it reaches listeners once the change commits and
  never when it rolls back. A refusal or a no-op reports nothing.

## Success Path

1. The application's administration screen authorises its user, then calls a helper with the tenant, the connection and
   a `Caller` for that user on their session.
2. The helper finds the connection, validates what it was given and asks the freshness contract for that caller.
3. In one transaction on the storage connection it writes, then calls `AdministrationEvents`, which builds the event's
   context from the connection and the caller's identity, as the acting identity, and hands the event to the
   after-commit dispatcher.
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
- Disabling a disabled connection asks for freshness and reports nothing. Deleting a connection reports one
  `ConnectionDeleted` and no event for each of the links, domains, keys, requests or handoff codes deleted with it.
- A caller whose identity has an empty or overlong type or id, or whose session id is empty or longer than 255 bytes, is
  the application's mistake: an `InvalidArgumentException` before any helper runs.
- `ExpiryReport::report()` given 0, a negative number or more than 365 days throws an `InvalidArgumentException`,
  `An expiry report looks 1 to 365 days ahead.`, before anything is read; a malformed `sso.keys.expiry_thresholds`
  fails closed with `KeySettings`' exception naming the key. Called twice, it lists the same rows twice and warns only
  of what has newly become due.
- A listener's exception propagates as Laravel's dispatcher propagates it, after the change has committed.

## Implementation Anchors

- `src/Administration/AdministrationEvents.php`, `src/Identities/Caller.php`, `src/Administration/DomainEvents.php`,
  `src/Administration/EnforcementEvents.php`.
- `src/Events/ConnectionCreated.php`, `ConnectionUpdated.php`, `ConnectionEnabled.php`, `ConnectionDisabled.php`,
  `ConnectionDeleted.php`, `KeyAdded.php`, `KeyMadeCurrent.php`, `KeyRetired.php`, `KeyNearingExpiry.php`.
- `src/Events/EventContexts.php`, `src/Events/AfterCommitDispatcher.php`: the projection and the dispatch.
- `src/Connections/ConnectionService.php`: `create()`, `update()` (`changeLocked()`, `changedSettings()`), `enable()`.
- `src/Connections/ConnectionLifecycle.php`: `disable()`, `delete()`; `src/Connections/SubjectMigration.php`:
  `migrate()`.
- `src/Keys/KeyService.php`: `insertOwnKey()`, `insertTrusted()`, `promote()`, `remove()`.
- `src/Keys/ExpiryReport.php`: `report()`; `src/Keys/ExpiryNotifier.php`: `notify()`; `src/Keys/KeySettings.php`:
  `expiryThresholds()`, `expiryClaimSeconds()`.
- `src/Freshness/FreshnessGate.php`, `src/Testing/FakeFreshness.php`.

## Authoritative Tests

- `tests/Unit/Events/AdministrationEventClassesTest.php`
  `testEachIsAPackageEventReturningItsContext`, `testEachSurvivesASerializeRoundTrip`,
  `testEachHoldsExactlyItsDeclaredProperties`, `testConnectionUpdatedHoldsAListOfNamesOnly`.
- `tests/Feature/Administration/AdministrationEventsTest.php`
  `testReportsEachConnectionChange`, `testAnUpdateThatChangedNothingReportsNothing`, `testReportsEachKeyChange`,
  `testAKeyWithNoEndOfValidityIsNeverNearingExpiry`, `testReportsOnlyOnceTheChangeCommits`.
- `tests/Feature/Administration/FreshnessConventionTest.php` `testTheCallerAskedAboutIsTheOneTheEventNames`.
- `tests/Unit/Identities/CallerTest.php` `testRefusesAMalformedSessionId`.
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
  `testTheDefaultWindowIsTheLargestThreshold`, `testTheConfiguredThresholdsSetTheWindow`,
  `testAGivenWindowReplacesTheDefault`, `testExpiredRowsAreIncluded`, `testARetiringKeyPastItsOverlapIsExcluded`,
  `testAKeyWithNoEndOfValidityIsNeverReported`, `testOrdersByEndOfValidityThenId`,
  `testReportsEachRowOnceWithNoActingIdentity`, `testAWarningIsSentOnceAndRecorded`,
  `testAKeyAlreadyNotifiedIsStillListed`, `testSkipsARowWhoseConnectionIsGone`, `testChangesNothingButTheMarker`,
  `testReadsTheWriteConnection`, `testRefusesADayCountOutOfRange`, `testAcceptsTheEdgesOfTheRange`.
- `tests/Integration/Administration/AdministrationEventsAfterCommitTest.php`
  `testAnOperationRolledBackWritesAndReportsNothing`, `testAnOperationCommittedReportsOnlyAfterTheCommit`,
  `testATransactionOnAnotherConnectionDefersNothing`, `testAQueuedListenerReceivesTheUpdateIntact`.
- `tests/Integration/Administration/NoSecretInAdministrationEventsTest.php`
  `testNoEventHoldsASecretOrASettingValue`.
- `tests/Unit/Events/DomainAndEnforcementEventClassesTest.php`,
  `tests/Feature/Administration/DomainAndEnforcementEventsTest.php`,
  `tests/Integration/Domains/DomainEventsAfterCommitTest.php`.

## Change Triggers

Update this note when any of the following change:

- an administration event, its fields, or what its context carries
- the helper that dispatches an event, or the order of a helper's events
- the order or the names `ConnectionUpdated` gives
- whether a refusal or a no-op reports anything
- the after-commit dispatch of administration events
- the operations a change asks the freshness contract about
- the nearing-expiry report's window, what it includes or leaves out, or anything it writes or enforces
