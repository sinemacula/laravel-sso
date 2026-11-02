# Connection Settings and Management Helpers

## Purpose

This note records how a connection's SAML and OIDC settings are validated, defaulted and stored, how its attribute
mapping is checked and applied, how its secrets are kept apart from its settings, and how the management helpers
create, update, read, list and enable a tenant's connections (SSO-1.2, SSO-2.3, SSO-2.4, SSO-2.5, SSO-2.10, SSO-2.11,
SSO-2.12), and how an update that changes the connection's trust voids what is in flight through it and is refused,
when it alters what subjects mean, while the connection has links (SSO-2.13). Disabling, deleting and the subject
migration are in `connection-lifecycle.md`; metadata and discovery import, and keys and certificates, have notes of
their own.

## Invariants

- A protocol's settings are a `Contracts\ProtocolSettings`: `Protocols\Saml2\Saml2Settings` and
  `Protocols\Oidc\OidcSettings` for the package's protocols. Their names, and how a change to each is classified, are
  `Saml2Setting` and `OidcSetting`'s: `freshnessFor()`, `subjectNames()` and `secretNames()` delegate to the enums.
- `fromArray()` never throws on what it is given. `violations()` reports each problem as a
  `Connections\SettingViolation` (a dotted path from the top, `signature_algorithms.2`, `extra_parameters.state`, and a
  `ViolationCode`), never the value. A value of the wrong type, malformed, outside its allow-list or past its cap is a
  violation, and so is a conditional requirement (`subject_attribute` when the subject comes from an attribute,
  `idp_initiated_start_url` when IdP-initiated sign-in is on). A missing required setting is not: a connection may be
  saved incomplete, `isComplete()` says when it is not, and only a complete connection is ever usable (SSO-2.1).
- A name the protocol does not have is `unknown`. A setting given as `null` is not given. A key that cannot be named
  (empty, carrying a control character, or too long for a violation's path) is reported at its parent, `settings` at
  the top.
- `toArray()` is what is stored: every setting given or with a default, defaults applied, in the order the enum names
  them, so a stored connection holds its settings explicitly and an update compares like with like.
- Settings that a feature switch gates (`require_encrypted_assertions` with `encrypted_assertions`, `idp_initiated`
  with `idp_initiated`) are `unsupported` while the switch is off; a malformed switch fails closed with
  `Config\Features::enabled()`'s `InvalidArgumentException`.
- The shared checks (a bounded string with no control character, an `https` URL, a boolean, a value from an
  allow-list, a list) live in `Connections\SettingRules`, so every class judges alike. A URL is absolute, with a host,
  no userinfo and no fragment, at most 2048 bytes; a well-formed URL of another scheme is `not_https`. The OIDC issuer
  also takes no query, and is stored exactly as given, never normalised (SSO-2.8).
- The OIDC extra parameters come from an allow-list; a parameter the flow controls is `reserved` whatever its case, so
  none can be set or overridden (SSO-2.4). The SAML algorithms never include SHA-1 or RSA 1.5, AES-CBC is accepted
  only when listed, and an encryption list needs a key transport and a data algorithm (SSO-6.7). The ID token
  algorithms are asymmetric only (SSO-7.3).
- A secret never travels among the settings: the helpers take each name `secretNames()` declares out of what is given
  before the settings see it, so a `client_secret` among OIDC settings is `reserved`. A secret is a string of 1 to
  1024 bytes with no control character; a client secret given to a client that authenticates with `private_key_jwt`
  is `unsupported`.
- `Connections\ConnectionSecrets` keeps the `secrets` column as a JSON object of each secret's name and its
  `SecretEncrypter` ciphertext, each encrypted on its own, or `null`. Which are set is read from the names alone, so a
  summary masks them (`Secrets\MaskedSecret`) without decrypting one; only `reveal()` decrypts, into a
  `Secrets\Secret`. A malformed column is an `UnexpectedValueException` naming neither its content nor a secret; the
  encrypter's failures propagate. It also judges the secrets a change gives and names those the change alters, so
  every helper treats a secret alike.
- `Connections\AttributeMapping` maps each target of the result from a SAML attribute or OIDC claim. The defaults are
  the OIDC standard claims and the SAML attributes by their OIDs. A target is standard (`email`, `given_name`,
  `family_name`, `display_name`, `groups`) or a custom lower-case name, at most `max_custom_attributes` of them; the
  result's own fields are `reserved` targets, and over OIDC a protocol value or a token is a `reserved` source
  (SSO-2.10). `map()` builds profile data: single values for the standard targets, `groups` always a list, every
  string cut to `max_value_length` characters and a list to `max_values` strings. Nothing mapped selects an identity
  (SSO-8.2).
- Every helper is scoped to a tenant (an opaque id of 1 to 255 bytes; anything else is an `InvalidArgumentException`)
  and finds a connection only through `Connections\ConnectionFinder`, on the write connection: another tenant's
  connection is `connection_not_found` to a change and `null` to `get()`.
- A change follows `outcomes.md`'s order: find the connection, locked; refuse an unavailable protocol; validate the
  whole connection as it would be stored; ask `Freshness\FreshnessGate`; write through the model, in one transaction on
  the storage connection; report through `Administration\AdministrationEvents` inside it. A refusal writes and reports
  nothing. The result is a `Connections\ConnectionResult`: `created`, `updated` (with the names that changed),
  `unchanged`, `enabled`, `refused` (`freshness_required`, `connection_not_found`, `protocol_unavailable`,
  `connection_has_links`) or `invalid` (`settings_invalid`, with every violation); `connection-lifecycle.md` adds
  `disabled`, `deleted` and `migrated`.
- An update that changes a setting the protocol's `subjectNames()` lists (the OIDC `issuer` and `client_id`; the SAML
  `idp_entity_id`, `subject_source`, `subject_attribute` and `name_id_format`) is refused with `connection_has_links`
  while the connection has a link, active or reserved with a reservation that expires after now, found by a locking
  read on the write connection once freshness has answered `fresh`; nothing is written. `Connections\SubjectMigration`
  makes such a change and relinks or removes the links in the same transaction (`connection-lifecycle.md`).
- An update whose operations include `sso.connection.trust` (a trust setting or a secret changed) voids, in its
  transaction and under the connection's lock, every unfinished authorisation request and unredeemed handoff code of
  the connection (`Connections\InFlightVoider`); an update that asks only `sso.connection.idp_initiated`, or nothing,
  voids nothing.
- `ConnectionService` stays at twenty methods: the steps of an update after the lock are its one `@internal` method,
  `changeLocked()`, which the subject migration reuses with its relinks' violations and its own freshness.
- Creating asks `sso.connection.trust` and the operation of each setting and secret given; an update asks only the
  operations of what changed (the display name and the mapping need none, and a change that changes nothing asks
  nothing); enabling always asks `sso.connection.enable`, even for an enabled connection. Each operation is asked
  once, in the order `FreshnessOperation` lists them, with its configured maximum age.
- A new connection is disabled. Enabling needs no complete settings, and never writes `has_completed_sign_in`. The
  tenant and the protocol never change: an update naming either is `immutable`.

### Linking and evidence settings

A connection's linking settings and evidence policy are columns of their own, outside the protocol settings, written by
`Connections\LinkingPolicyService` and `Connections\EvidenceSettingsService` (`linking.md`, `evidence.md`). Both ask
`sso.connection.trust`; neither raises the trust version or voids a flow.

## Success Path

1. `create()` checks the tenant id, the protocol's availability and the preset; fills in the preset's settings and
   mapping under what is given and the protocol's default mapping; takes out the secrets; validates the display name,
   the settings, the secrets and the mapping, in that order; asks freshness; inserts the connection, disabled, and
   reports `ConnectionCreated`.
2. `update()` locks the connection, merges the changes (a value replaces, `null` removes, a secret not named is kept),
   validates the merged connection, names what changed (settings in the enum's order, then secrets, `display_name`,
   `attribute_mapping`), asks freshness for what changed, refuses a subject change while the connection has links,
   saves, voids what is in flight when it asked `sso.connection.trust`, and reports `ConnectionUpdated` with those
   names.
3. `get()` and `list()` read on the write connection and answer `ConnectionSummary` values: settings, masked secrets,
   mapping, flags, whether the connection is usable now, and its times in UTC.
4. `enable()` locks the connection, asks freshness, sets `enabled` and reports `ConnectionEnabled`.

## Failure / Edge Cases

- An unknown preset is `unknown` at `preset`; a preset of another protocol is `not_allowed` there.
- An update that gives what is stored, clears a secret that is not set, or enables an enabled connection is
  `unchanged`: nothing is written or reported, and only enabling asks freshness.
- A stored connection that has become invalid (a feature switched off under it) cannot be updated until the change
  also fixes it; the violations say what.
- A database error, a `SecretEncrypter` that cannot encrypt, and a malformed configuration (a mapping cap, a maximum
  age, a feature switch) propagate; nothing is written.
- A connection whose protocol is no longer registered is listed and read with no secrets declared and never usable; it
  cannot be changed or enabled (`protocol_unavailable`).
- A stale caller changing a subject setting is `freshness_required`, whatever the links; a link of another connection,
  and a reservation that expired at now or before, do not count.
- A refused or unchanged update voids nothing; a voided request or code keeps its first `voided_at`.

## Implementation Anchors

- `src/Protocols/Saml2/Saml2Settings.php`, `src/Protocols/Oidc/OidcSettings.php`, `src/Connections/SettingRules.php`.
- `src/Connections/AttributeMapping.php`, with its caps in `src/Connections/MappingLimits.php` and
  `src/Connections/MappingCheck.php`.
- `src/Connections/ConnectionSecrets.php`.
- `src/Connections/ConnectionService.php`, `src/Connections/ConnectionResult.php`,
  `src/Connections/ConnectionSummary.php`, `src/Connections/Enums/ConnectionStatus.php`.

## Authoritative Tests

- `tests/Feature/Protocols/Saml2/Saml2SettingsTest.php`: `testAppliesTheDefaults`,
  `testReportsEachViolationAtItsSetting`, `testRequiresTheFeatureForEncryptedAssertions`,
  `testRequiresTheFeatureAndAStartUrlForIdpInitiatedSignIn`, `testAMalformedFeatureSwitchFailsClosed`,
  `testIsCompleteWithTheEntityIdAndSingleSignOnUrl`, `testTakesItsClassificationFromTheSettingEnum`.
- `tests/Feature/Protocols/Oidc/OidcSettingsTest.php`: `testStoresWhatIsGivenExactlyInTheOrderTheSettingsAreNamed`,
  `testReportsEachViolationAtItsSetting`, `testNeverSetsAParameterTheFlowControls`,
  `testIsCompleteWithTheIssuerEndpointsAndClientId`, `testTakesItsClassificationFromTheSettingEnum`.
- `tests/Unit/Connections/AttributeMappingTest.php`: `testHasDefaultsForEachPackageProtocol`,
  `testRefusesAReservedTarget`, `testRefusesAnOidcProtocolValueOrTokenAsASource`, `testCapsTheCustomTargets`,
  `testMapsGroupsToAList`, `testCutsEveryValueToTheCap`.
- `tests/Feature/Connections/MappingLimitsTest.php`, `tests/Feature/Connections/MappingCheckTest.php`.
- `tests/Feature/Connections/PresetSettingsTest.php`: `testEveryPresetIsValid`.
- `tests/Feature/Connections/ConnectionSecretsTest.php`: `testNamesAndMasksWithoutDecrypting`,
  `testAppliesEachChangeOnItsOwn`, `testRefusesAMalformedColumn`.
- `tests/Unit/Connections/ConnectionResultTest.php`, `tests/Feature/Connections/ConnectionSummaryTest.php`.
- `tests/Feature/Connections/ConnectionServiceTest.php`: `testCreatesADisabledConnection`,
  `testFillsInAPresetAndLetsWhatIsGivenReplaceIt`, `testCollectsEveryViolationInOrder`,
  `testKeepsTheStoredSecretWhenAnUpdateDoesNotNameIt`, `testRefusesAnImmutableOrUnknownKey`,
  `testAsksTheFreshnessOfWhatChanged`, `testAnUpdateThatChangesNothingIsUnchanged`, `testRefusesAStaleCreation`,
  `testRefusesAStaleUpdate`, `testRefusesAStaleEnable`, `testAnUpdateFindsOnlyTheTenantsConnection`,
  `testEnablingNeverWritesTheCompletedSignIn`, `testASubjectChangeIsRefusedWhileTheConnectionHasALink`,
  `testOnlyAnUnexpiredReservationCountsAsALink`, `testAStaleSubjectChangeIsRefusedForFreshnessFirst`,
  `testATrustChangeThatAltersNoSubjectIsAllowedWithLinksAndVoids`.
- `tests/Feature/Connections/TrustChangeVoidingTest.php`: `testATrustChangeVoidsOnlyWhatIsInFlight`,
  `testEachTrustChangeVoids`, `testAnyOtherChangeVoidsNothing`.
- `tests/Integration/Connections/ConnectionServiceTest.php`: `testStoresTheSecretOnlyAsCiphertext`,
  `testSecretsSurviveAnAppKeyRotation`, `testAnEncrypterThatCannotEncryptPropagates`, `testReadsTheWriteConnection`.
- `tests/Performance/ConnectionServiceQueryBudgetTest.php`, `tests/Performance/ConnectionLifecycleQueryBudgetTest.php`.

## Change Triggers

- A setting, its rule, its allow-list or its default; a new protocol shipped with settings of its own.
- What a mapping may target or read, its defaults, or how a mapped value is capped.
- How secrets are stored, masked or revealed.
- A management helper's order of steps, its outcomes, the operations it asks freshness for, or the events it reports.
- Which settings alter what subjects mean, what counts as a link, or which changes void what is in flight.
