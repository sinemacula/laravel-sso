# SAML Responses

## Purpose

This note records how the SAML driver correlates a response posted to a connection's assertion consumer service and
validates it against the request consumed for it (SSO-5.3, SSO-5.8, SSO-6.2 to SSO-6.11), and what it answers the
completion: the verified claims and the replay record of the assertion, or one failure reason. Parsing, structure,
signatures and decryption are the SAML adapter's (`saml-adapter.md`); consumption, the completion's locks and the
recording of the replay record are the completion's (`completion.md`, `flows.md`); the completion path of the
unsolicited profile is re-initiation's (`idp-initiated.md`). Everything here judges only values the adapter read from
verified elements.

## Invariants

- Correlation validates nothing and keeps nothing. Only an HTTP-POST whose `SAMLResponse` is a non-empty string is read,
  through `SamlAdapter::envelope()`. No `InResponseTo` anywhere is unsolicited; `InResponseTo` values that disagree, or
  an id that is empty or longer than 255 bytes, are uncorrelated, never unsolicited. Otherwise the response names its
  request by the one id, with its `RelayState` as the protocol state when that is a string of at most 80 bytes.
- The request is found by the connection and its SAML request id, consumed before anything is validated, and refused
  with `request_mismatch` when the `RelayState`'s digest is not its state digest or there is no `RelayState`
  (`Flows\RequestConsumption`). An unknown id is `request_unknown`.
- One core validates every profile (`Validation\AssertionValidator`): the solicited path gives it the consumed request,
  the unsolicited profile (SSO-5.8) gives it none, and which rules apply depends only on that. A solicited response with
  no consumed request, and an unsolicited one with a consumed request, are `request_unknown`.
- Every rule reads one instant, the clock's now once the response is read, with the skew of `sso.clock.skew_seconds`
  (default 60, at most 300). A bound that starts a window may be up to the skew after now; a bound that ends one is
  passed only once now is the skew beyond it. `SessionNotOnOrAfter` is never extended by the skew.
- Identity and correlation come only from signed content: the subject, conditions, confirmations, statements and
  attributes are the verified assertion's, and the authenticated `InResponseTo` is the bearer confirmation's. The
  response's own `InResponseTo`, and every other bearer confirmation's that names one, must agree with it.
- The subject is a versioned, length-prefixed tuple, at most 1024 bytes, never truncated, trimmed or normalised:
  `v1`, then for each part `|` and its byte length, `:` and the part, or `-` when absent. A `NameID` subject is
  (`name_id`, `Format`, `NameQualifier`, `SPNameQualifier`, value); an attribute subject is (`attribute`, `Name`,
  `NameFormat`, value). An absent part and an empty one differ, so a qualifier or format that appears, disappears or
  changes makes a different subject, and a link made for one never matches the other.
- The replay record is the assertion's id, scoped by the connection and the issuer (`Protocols\ReplayRecord`), until
  the last moment any rule would still accept the assertion: the earliest of the `Conditions`' `NotOnOrAfter`, the
  chosen bearer confirmation's `NotOnOrAfter` and the assertion's `IssueInstant` plus
  `sso.saml2.issue_instant_max_age_seconds`, each plus the skew. Every bound is read from inside the signed assertion,
  never from the envelope a replay may carry afresh. Validation never records it: the completion records it under the
  connection's lock after validation (`Completion\Stages\RecordReplay`), so an invalid assertion records nothing.
- Nothing of the response is logged, reported or kept. A refused read logs the adapter's rule in the package's own
  words; an unsuccessful status logs its codes and its `StatusMessage` through the sanitising logger, never in an event
  or a result. The request's public reference is the only flow identifier a log carries.

## Success Path

1. `ResponseCorrelator::correlate()` reads the envelope and names the request; the completion consumes it.
2. `ResponseValidator::complete()` hands the response to `AssertionValidator::validate()` with the consumed request.
3. The adapter reads the response with the connection's `ResponsePolicy` (`Validation\ResponsePolicies`): its trusted
   `idp_signing` certificates, its signature, key transport and data encryption algorithms, and a closure that reads
   and decrypts its decryption keys only when the assertion is encrypted.
4. The profile is checked, then, in order: `ResponseRules` (issuers, `Destination`, required encryption, the
   assertion's own signature), `ConditionRules` (`NotBefore`, `NotOnOrAfter`, every `AudienceRestriction`, unknown
   conditions, both `IssueInstant`s), `BearerConfirmations` (the response's `InResponseTo` and every bearer
   confirmation's, then one bearer confirmation satisfying every rule on its own), `SubjectRules` with
   `SubjectEncoding`, and `AuthenticationRules`.
5. The response is verified with `VerifiedClaims` (the identity provider's entity id, the subject, the format URI or
   `null` for an attribute subject, every attribute statement's string values by name, the authentication context, no
   linking email yet) and the `ReplayWindow` record.

## Failure / Edge Cases

- An unsuccessful status: its `Issuer` and `Destination` are held to the same rules, an absent `Issuer` refused, and
  its `InResponseTo` must be the consumed request's, before it is `provider_error`.
- `issuer_mismatch`: the response's `Issuer` or the assertion's is absent or is not the connection's entity id. SAML
  2.0 Profiles §4.1.4.2 lets an unsigned response with a plain assertion leave its `Issuer` out; the package refuses
  that too, since SSO-6.4 holds both issuers to the entity id.
- `recipient_mismatch`: the `Destination` is absent, or is not exactly the assertion consumer service, whether or not
  the response is signed (an unsigned response's `Destination` is not authenticated, but its absence is never taken
  as a pass); or no bearer confirmation names the service as its `Recipient`.
- `encryption_required`: a plain assertion where the connection requires encryption.
- `signature_invalid`: the connection wants assertions signed (the default) and the assertion carries no signature of
  its own.
- `assertion_expired`: a `Conditions` bound, a bearer confirmation without `NotOnOrAfter`, with `NotBefore` or past its
  `NotOnOrAfter`, an `IssueInstant` in the future or too old, or an `AuthnInstant` in the future.
- `audience_mismatch`: any `AudienceRestriction` without the service provider's entity id, an empty one included.
  `Conditions` may be absent. `OneTimeUse` and `ProxyRestriction` are accepted; any other condition, even one of a type
  the schema knows, is `condition_unsupported`.
- `request_mismatch`: the response's or the chosen confirmation's `InResponseTo` is not the consumed request's id, or
  any bearer confirmation names another request (inside an encrypted assertion too, which the envelope cannot see). With
  no confirmation satisfying every rule, the reason is that of the rule broken by the candidate that got furthest, the
  first in document order on a tie; of those satisfying every rule, the latest to expire is chosen, the first on a tie.
- `subject_invalid`: no `NameID`, a format that is not the connection's (`transient` never is; an absent `Format`
  matches only `unspecified`), a qualifier that is not its party's, an empty value, an attribute subject absent,
  repeated, multi-valued or empty, or an encoding over 1024 bytes.
- `response_invalid`: not exactly one `AuthnStatement`, or a `SessionIndex` or class the authentication context cannot
  hold; `authentication_expired`: too old for `max_authentication_age_seconds`, earlier than a `reauthenticate`
  request's start less the skew, or a `SessionNotOnOrAfter` not after now; `authentication_context_mismatch`: a class
  other than one of `requested_authn_context`.
- A read the adapter refuses keeps its reason (`response_invalid`, `signature_invalid`, `decryption_failed`), every
  decryption failure the same.

## Implementation Anchors

- `src/Protocols/Saml2/ResponseCorrelator.php`, `src/Protocols/Saml2/ResponseValidator.php`
- `src/Protocols/Saml2/Validation/`: `AssertionValidator.php`, `ValidationContext.php`, `ResponsePolicies.php`,
  `ResponseRules.php`, `ConditionRules.php`, `BearerConfirmations.php`, `SubjectRules.php`, `SubjectEncoding.php`,
  `AuthenticationRules.php`, `ReplayWindow.php`
- `src/Protocols/ReplayRecord.php`, `src/Completion/Stages/RecordReplay.php`

## Authoritative Tests

- `tests/Feature/Completion/SamlAdversarialCompletionTest.php`: every hostile case of the review focus through the
  public completion path.
- `tests/Feature/Completion/SamlFixtureCompletionTest.php`: the 40 fixtures of the library comparison through the public
  completion path, each with the outcome the manifest records.
- `tests/Feature/Completion/SamlCompletionTest.php`, `tests/Feature/Completion/SamlCompletionEventSequenceTest.php`
- `tests/Integration/Completion/ConcurrentSamlReplayTest.php`
- `tests/Integration/Completion/SamlTrustChangeRaceTest.php`
- `tests/Performance/SamlCompletionQueryBudgetTest.php`
- `tests/Feature/Protocols/Saml2/ResponseCorrelatorTest.php`, `tests/Feature/Protocols/Saml2/ResponseValidatorTest.php`
- `tests/Feature/Protocols/Saml2/Validation/` and `tests/Unit/Protocols/Saml2/Validation/SubjectEncodingTest.php`

## Change Triggers

- A new subject source or kind of identifier: a new kind in the encoding, never a change to `v1`'s layout.
- A new condition the package understands: its own rule, and its removal from the refused set.
- A change to the clock skew or the maximum ages: the replay record's expiry follows the same bounds.
- Linking by a verified domain (P6): the linking email joins the claims.
