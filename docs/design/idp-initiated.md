# IdP-Initiated Sign-In

## Purpose

This note records how the package answers an unsolicited SAML response, one the identity provider sent without the
service provider asking (SSO-5.8, SSO-6.11): it is validated in full by the unsolicited profile, recorded against
replay, and answered by re-initiation, a redirect to the connection's application start URL so the application starts
an ordinary SP-initiated flow. It never signs anyone in. Correlation, validation and replay recording are the SAML
driver's and the completion's (`saml-responses.md`, `completion.md`); the lock order is `flows.md`'s.

Consuming an unsolicited assertion directly is not supported. Such an assertion is bound to no request and no client,
so the package cannot tell who posted it:

- Login CSRF: an attacker who holds a valid assertion for their own account can make a victim's browser post it, signing
  the victim into the attacker's account; whatever the victim then enters is the attacker's to read.
- An intercepted assertion: one taken from a log, a proxy, the browser's history or a shared machine can be posted by
  anyone within its validity window. The replay cache refuses a second use, never the first.

Re-initiation keeps what IdP-initiated sign-in is for (a user starting from the identity provider's portal) without
either risk: the response is only a hint that the user wants to sign in through the connection; the sign-in itself is
SP-initiated, bound to a stored request, its `RelayState` and the browser that started it, and the identity provider
completes it from the session it already has.

## Invariants

- Off by default, per connection: the connection's `idp_initiated` setting, which may be on only while
  `sso.features.idp_initiated` is, and then needs `idp_initiated_start_url`, an `https` URL without credentials or
  fragment (`Saml2Settings`). Turning the feature off makes every connection that still holds the setting incomplete.
- Only a response with no `InResponseTo` anywhere is unsolicited: not on the response, not on any bearer confirmation,
  and not inside an encrypted assertion. One with an `InResponseTo` naming no stored request is `request_unknown`, never
  unsolicited; one naming a stored request is solicited and completes that request (`saml-responses.md`).
- The correlation step hands an unsolicited response to re-initiation only when the connection's driver implements
  `Contracts\ReinitiatingDriver` (the SAML driver); any other driver's is `request_unknown`. No other step may hand a
  completion over: that is a `LogicException`.
- The unsolicited profile is every rule of a successful response (`Validation\AssertionValidator` with no consumed
  request): signatures and wrapping defences, issuers, destination, encryption, conditions, audiences, one bearer
  confirmation, the subject and the authentication context. Expired metadata is refused first with `metadata_expired`.
- No authorisation request is consumed or created, no link resolved, no result verified and no handoff code issued. The
  unsolicited identity (its subject, attributes and authentication context) goes no further than the validator, so
  nothing of it carries into the flow the application starts next.
- Validation runs outside any transaction, on the connection as the completion read it, whose trust version is captured
  first. The assertion is recorded only after validation, inside one transaction holding the connection's row lock
  alone (a locking read on the write connection; no enforcement, request or code row), and only once the locked
  connection is still there, usable and at the same trust version, its refreshed metadata has not expired by now, it
  still allows IdP-initiated sign-in, and the driver's start URL for it (`ReinitiatingDriver::startUrl()`) is still the
  one validated with. An opt-in or start URL change voids nothing and leaves the trust version alone, so it is this
  recheck that refuses a response validated before it. An invalid assertion, or one refused under the lock, records
  nothing.
- The record is made exactly as a solicited response's (`Completion\Stages\RecordReplay`, resolved for the
  `replay_recording` step): scoped by connection and issuer, until its last acceptance moment; one whose expiry is no
  longer after now is `assertion_expired`, one recorded before is `replayed`.
- The start URL is the configured one with the query parameter `connection` set to the connection's id, after a `?`
  when the URL has no query and after an `&` when it has one (directly when it already ends in `?` or `&`). The posted
  `RelayState` is never read, so it can never become a redirect target.
- Events report only: `UnsolicitedResponseReinitiated` once the record commits, or exactly one `FlowFailed` for the
  `assertion` flow, each naming the connection, its tenant and its protocol and nothing else of the flow (SSO-10.4). No
  event or log carries the response, the assertion, the `RelayState`, the `NameID` or an attribute's value; a
  connection that does not allow IdP-initiated sign-in logs a notice naming the connection alone.

## Success Path

1. `CompletionService::complete()`, at `CompletionEndpoint::ASSERTION_CONSUMER_SERVICE`, counts the attempt, checks the
   method and finds the connection.
2. `CorrelateResponse` asks the SAML driver to correlate; `ResponseCorrelator` finds no `InResponseTo` in the envelope,
   so the stage answers `StageOutcome::reinitiate()` with the unsolicited correlation and the pipeline runs no further
   step.
3. `UnsolicitedReinitiation` captures the connection's `trust_version` and calls `Saml2Driver::reinitiate()`, which
   refuses expired metadata and hands the response to `UnsolicitedResponses::reinitiate()`: the connection must allow
   IdP-initiated sign-in, then `AssertionValidator::validate()` runs the unsolicited profile and answers the replay
   record.
4. In one storage transaction the connection's row is locked for update; it is still there, usable
   (`ProtocolManager::isUsable()`), at the captured trust version, with metadata that has not expired
   (`MetadataExpiry`), and its start URL is still the one validated with, so the replay record is recorded through the
   single-use store.
5. After commit, `UnsolicitedResponseReinitiated` is dispatched and the completion answers
   `CompletionResult::reinitiated()` with the start URL confirmed under the lock; the application's controller turns
   it into a `303` to that URL (`completion-responses.md`).
6. The application's start route reads `connection`, starts an SP-initiated `sign_in` through it, and the identity
   provider answers that request from its existing session.

## Failure / Edge Cases

- `unsolicited_not_allowed`: the connection's `idp_initiated` is off; nothing posted is read. Turned off once the
  response is validated, it is found off under the lock, and nothing is recorded.
- `connection_unavailable`: the connection allows it but holds no start URL (an incomplete connection, never stored by
  the settings); or, under the lock, the connection is gone, disabled, incomplete (IdP-initiated sign-in turned off for
  the application included) or its trust version moved since validation began: a certificate distrusted, a metadata
  signing anchor changed, the connection disabled and enabled again; or its start URL changed since validation began.
  An additive identity provider certificate does not move the trust version, so it refuses nothing.
- `metadata_expired`: what a metadata refresh applied has expired, when the driver is entered or, checked again on the
  locked row, by the time the lock is taken.
- `request_unknown`: an `InResponseTo` on a bearer confirmation alone (the envelope names a request that is not stored),
  or inside an encrypted assertion alone (the unsolicited profile finds it once decrypted).
- `provider_error`: an unsuccessful status with no `InResponseTo`, its status logged sanitised as for any response.
- Every other reason of the unsolicited profile is the validator's (`saml-responses.md`): `signature_invalid`,
  `response_invalid` (signature wrapping, duplicate ids, two assertions), `issuer_mismatch`, `recipient_mismatch`,
  `audience_mismatch`, `assertion_expired`, `subject_invalid` (a transient `NameID` included) and the rest.
- `replayed`: the same assertion posted again, or two posts of it racing: the connection's lock orders them, and the
  second finds the record. On PostgreSQL a racer may instead fail to serialise (SQLSTATE `40001`), which records
  nothing and propagates as a server error.
- Every refusal is `rejected`, a `400` with no redirect: an unsolicited response has no trusted redirect target.
- A database error propagates as a server error and rolls the record back (SSO-11.4).

## Implementation Anchors

- `src/Completion/UnsolicitedReinitiation.php`, `src/Completion/CompletionPipeline.php`,
  `src/Completion/Stages/CorrelateResponse.php`, `src/Completion/StageOutcome.php`,
  `src/Completion/CompletionEvents.php`
- `src/Contracts/ReinitiatingDriver.php`, `src/Protocols/Reinitiation.php`, `src/Protocols/ReplayRecord.php`
- `src/Protocols/Saml2/Saml2Driver.php`, `src/Protocols/Saml2/UnsolicitedResponses.php`,
  `src/Protocols/Saml2/Validation/AssertionValidator.php`
- `src/Events/UnsolicitedResponseReinitiated.php`

## Authoritative Tests

- `tests/Feature/Completion/SamlReinitiationTest.php`: every case through the public completion path.
- `tests/Feature/Completion/SamlReinitiationEventSequenceTest.php`: the events, their context, and nothing of the
  response reported or logged.
- `tests/Integration/Completion/ConcurrentReinitiationTest.php`: two posts racing, and trust changes and IdP-initiated
  sign-in turned off between validation and the lock.
- `tests/Feature/Protocols/Saml2/UnsolicitedResponsesTest.php`, `tests/Feature/Completion/CompletionPipelineTest.php`,
  `tests/Feature/Completion/Stages/StagesTest.php`

## Change Triggers

- Another protocol with unsolicited responses: its driver implements `Contracts\ReinitiatingDriver`.
- A new trust change: it raises the trust version, so a re-initiation validated before it is refused.
- Consuming unsolicited assertions directly would need a new requirement, its own threat model and an opt-in of its
  own; it is deliberately out of scope.
