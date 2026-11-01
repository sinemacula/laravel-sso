# SAML Driver

## Purpose

This note records the `saml2` protocol driver as a whole (SSO-2.2, SSO-2.3, SSO-5.3, SSO-5.8, SSO-5.9, SSO-6): what
each of its calls does and which collaborator does it, how it plugs into the flow core without bypassing consumption,
the lock order or enforcement, and what it keeps. The parts are recorded in their own notes: the adapter in
`saml-adapter.md`, the request in `saml-requests.md`, the response in `saml-responses.md`, re-initiation in
`idp-initiated.md`, the service provider metadata in `service-provider-metadata.md`, and metadata import and refresh in
`metadata-refresh.md`.

## Invariants

- `Protocols\Saml2\Saml2Driver` implements `Contracts\ProtocolDriver` and `Contracts\ReinitiatingDriver`, registered
  under `saml2` while `sso.features.saml2` is on. Every check of SSO-6 is always on; the settings choose only what the
  requirements leave to a connection (`Saml2Settings`).
- Each call reads the connection's settings afresh into `Saml2Options` and hands them to one collaborator:
  - `settings()`: `Saml2Settings`, the validation of every SAML setting;
  - `isComplete()`: the settings are complete, the connection trusts at least one `idp_signing` certificate, and it
    has a current `sp_signing` key when it signs its `AuthnRequest`s and a current `sp_encryption` key when it requires
    encrypted assertions;
  - `start()`: `AuthnRequests`, which writes the `AuthnRequest` through the adapter and answers a `Start` naming its
    `ID`, stored as `saml_request_id` for the response's `InResponseTo`;
  - `correlate()`: `ResponseCorrelator`, which reads the envelope and validates nothing;
  - `complete()`: `ResponseValidator`, which holds the response to every rule of its profile through
    `Validation\AssertionValidator` and answers the verified claims with the assertion's `Protocols\ReplayRecord`;
  - `reinitiate()`: `UnsolicitedResponses`, the unsolicited profile, for re-initiation alone;
  - `describe()`: `ServiceProviderMetadata`, the connection's service provider metadata.
- `start()`, `complete()` and `reinitiate()` are refused with `metadata_expired`, before their collaborator is asked,
  while what a metadata refresh applied to the connection has expired (`Metadata\MetadataExpiry`, SSO-2.8). The
  completion and the re-initiation check expiry again on the locked connection, so metadata that lapses while the
  response is validated is refused there too, recording nothing.
- `startUrl()` answers the start URL re-initiation sends the browser to, naming the connection, or `null` when the
  connection does not allow IdP-initiated sign-in; the re-initiation asks it again of the locked connection.
- Only the adapter's namespace (`Protocols\Saml2\Library`) calls the SAML library. The driver and its collaborators
  read only the package's own values (`Protocols\Saml2\Messages`), each holding what the identity provider sent in a
  `\SensitiveParameterValue`.
- The driver never consumes, locks, records or writes. The flow core does, in its fixed order (`completion.md`):
  1. `correlation`: the driver's `correlate()`, outside any transaction;
  2. `consumption`: the request found by `(connection, saml_request_id)` is consumed in a transaction of its own, the
     connection's row locked before the request's, and the `RelayState`'s digest compared with its state digest, before
     anything in the response is validated, so a response is consumed once whether it then passes or fails;
  3. `validation`: the driver's `complete()` against the consumed request, outside any transaction, with the
     connection's trusted certificates read for it;
  4. `replay_recording` and every later step: one transaction that takes the global lock order (the enforcing tenant's
     guard when enforcement applies, then the connections in ascending id order, then the request), refuses a
     connection no longer usable (its trust read again under the lock) or a request a trust change voided since
     consumption, records the assertion's id through the single-use store, then resolves the link, judges enforcement
     and issues the handoff code.
- An unsolicited response is handed by the correlation step to `Completion\UnsolicitedReinitiation`, which consumes no
  request: it asks the driver's `reinitiate()`, records the assertion under the connection's lock after rechecking its
  trust version, usability, metadata expiry and start URL, and answers a redirect to the connection's start URL. The
  unsolicited identity never reaches a link, an enforcement decision or a handoff.
- The protocol manager keeps one driver per process (and per application under Octane): the driver and its
  collaborators hold no connection, flow or result state between calls (SSO-11.2).

## Success Path

1. The application starts a sign-in through `Flows\AuthorizationRequestService`; the driver's `start()` answers the
   `AuthnRequest` by HTTP-Redirect or HTTP-POST with the flow's state as `RelayState`, and the request is stored with
   its `ID`.
2. The identity provider posts the response to the connection's assertion consumer service; the application's route
   calls `CompletionService::assertionConsumerService()`.
3. Correlation names the request, consumption consumes it, validation verifies the response, and the locked steps
   record the assertion, resolve the link, judge enforcement and issue the handoff code.
4. The application answers the `CompletionResult` with a `303` to its redirect URI carrying the code.

## Failure / Edge Cases

- A post the driver cannot read, or whose `InResponseTo` values disagree, names no request: `request_unknown`, a `400`
  with no redirect and nothing consumed.
- A response that names a request but fails validation has consumed it: the failure redirects to the request's
  application with the driver's reason, and nothing is recorded against replay.
- A trust change (a certificate distrusted, an endpoint moved by a metadata refresh, a disable) between validation and
  the lock voids the request: the completion is refused with `connection_unavailable` under the lock.
- The same assertion posted twice: the second post finds its request consumed (`request_unknown`), and an assertion
  replayed against another request is refused with `replayed` by the record made the first time.

## Implementation Anchors

- `src/Protocols/Saml2/Saml2Driver.php`, `Saml2Settings.php`, `Saml2Options.php`, `Saml2Limits.php`,
  `Saml2Check.php`.
- `src/Protocols/Saml2/AuthnRequests.php`, `ResponseCorrelator.php`, `ResponseValidator.php`,
  `UnsolicitedResponses.php`, `ServiceProviderMetadata.php`.
- `src/Completion/Stages/RecordReplay.php`, `src/Completion/UnsolicitedReinitiation.php`,
  `src/Protocols/ReplayRecord.php`.

## Authoritative Tests

- `tests/Feature/Protocols/Saml2/Saml2DriverTest.php`, `Saml2SettingsTest.php`, `Saml2OptionsTest.php`,
  `Saml2LimitsTest.php`.
- `tests/Feature/Completion/SamlCompletionTest.php`, `SamlCompletionEventSequenceTest.php`,
  `SamlAdversarialCompletionTest.php` and `SamlFixtureCompletionTest.php` (the 40 library fixtures through the public
  completion helper).
- `tests/Integration/Completion/ConcurrentSamlReplayTest.php` and `SamlTrustChangeRaceTest.php` (MySQL and
  PostgreSQL).
- `tests/Performance/SamlCompletionQueryBudgetTest.php`.
- `tests/Unit/Architecture/SamlLibraryBoundaryTest.php`.

## Change Triggers

- A new call on `Contracts\ProtocolDriver`, or a change to the completion's steps, transactions or lock order.
- A new SAML setting, or a check of SSO-6 that a connection could switch off.
- A new binding, message kind or profile.
- The move to saml2 v7 (`saml-library.md`).
