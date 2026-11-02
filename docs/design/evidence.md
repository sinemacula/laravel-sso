# Evidence

## Purpose

This note describes what the package does with the identity provider's authentication context (SSO-8.7, SSO-9.5,
SSO-9.10): how a connection says which of its provider's assertions count, how a result is judged, and what a redeemer
receives. It amends nothing in `linking.md`: evidence stands on that state machine and adds no stage, no lock and no
event. The guide is `docs/guides/evidence.md`.

## Invariants

- The package never treats a provider's methods as satisfying a further factor. `Contracts\EvidencePolicy` decides
  whether they count, and its default, `Evidence\InsufficientEvidence`, says they never do. An application opts in by
  binding `Evidence\ConnectionEvidencePolicy`.
- Evidence is judged at redemption, by the policy the connection's row holds then, read under the redemption's lock on
  that row, and against the instant of the redemption. Neither the completion's policy nor its clock counts, and a
  code's short lifetime establishes nothing: a code redeemed later than the maximum age, though unexpired, has none.
- Evidence comes only from the result's own `AuthenticationContext`, which comes only from the validated assertion: the
  ID token (`ClaimsAssembler`, whatever UserInfo says) or the one `AuthnStatement` of the validated SAML assertion
  (`AuthenticationRules`). UserInfo or another assertion never strengthens it.
- Missing, malformed, unlisted, too old or too far in the future is `null`, never a pass and never an exception. A
  refusal of the evidence refuses nothing else: the redemption goes on, with no evidence to offer.
- `link` proves nothing. Its branch has no policy to ask, and `ConnectionEvidencePolicy` answers `null` for a `link`
  result whoever asks.
- `sign_in` asks only once an identity is established: after a reservation's activation, or for a link whose continuity
  held. An unlinked handoff and a refusal never ask.
- `reauthenticate` asks once its link and session are judged, and the renewal carries what this authentication gave and
  nothing earlier (SSO-9.5). The sign-in's provenance is the adapter's to keep apart (SSO-9.10).
- `AcceptedEvidence` holds only the accepted RFC 8176 methods, the raw context class as data, the connection's id as the
  credential reference and the provider's authentication time. No field is an assurance level. Its provider values are
  behind `\SensitiveParameterValue`, a dump and JSON show counts, and it refuses to be serialised or unserialised.
- No evidence value reaches a log, an event or an exception. Evidence adds no event.

### The policy

`connections.evidence_policy`, a JSON map, judged by `Evidence\EvidenceRules`:

| Name                      | Protocol     | What it holds                                                   |
|---------------------------|--------------|-----------------------------------------------------------------|
| `amr`                     | all but SAML | Accepted methods, at most 32, each once, each an RFC 8176 value |
| `acr`                     | all but SAML | Accepted classes, at most 32, each once, each 1 to 1024 bytes   |
| `authn_context_class_ref` | SAML         | Accepted classes, by the same rules as `acr`                    |
| `combinations`            | all          | What counts: 1 to 32 maps, any one of which is enough           |
| `max_age_seconds`         | all          | Optional: a whole number from 1, up to the ceiling              |

A combination names `amr`, a non-empty list every one of which the assertion must state, `acr`, the class it must state,
or both; on SAML, `authn_context_class_ref`. Each value must be one the policy lists. A combination naming nothing is
refused, since it would otherwise count anything. The connection's protocol decides which names it may hold, and a
stored policy naming another protocol's is malformed there. A driver an application registered reads as OIDC does: the
methods and class of its `AuthenticationContext` are its normalised evidence contract, populated only from its own
authenticated response, not an assumption that its wire protocol is OIDC.

`sso.linking.evidence_max_age_seconds` is the ceiling, and `max_age_seconds` may only tighten it: a value above the
ceiling is `not_allowed` when written, and a stored value is clamped to the ceiling as it is when read, so lowering the
ceiling later still wins, and never turns a stored policy malformed.

Only methods are filtered into the evidence. An asserted method the policy does not list is dropped, and a combination
it would have completed is not satisfied. The raw class is carried whether listed or not, since it is data; it satisfies
a combination only by being the one that combination names.

### Writing it

`Connections\EvidenceSettingsService` replaces the whole policy, with `sso.connection.trust` freshness, under the
connection's row lock, the only lock it takes, so it cannot invert the redemption's order (`linking.md`). A `set()` is
no protocol trust change and no linking change: `trust_version`, `linking_version` and `links_version` stay, and no
request, code or reservation is touched. It reports `ConnectionUpdated` once, after commit, with the names as
`evidence.*`, sorted, and no value; a refused or unchanged call reports nothing.

Reads and writes are judged by one set of rules, the ceiling apart, so nothing `set()` accepts can later read as
malformed and nothing else it refuses can be read as a policy. A row the package did not write is insufficient, and
`set()` can replace it.

### What a redeemer does with it

`RedemptionResult::$evidence` or `Admission::$evidence` for an adapter redeeming its own codes. Under `laravel-iam`:

| Purpose          | Proof for `laravel-mfa`                                            |
|------------------|--------------------------------------------------------------------|
| `sign_in`        | `first_factor`                                                     |
| `reauthenticate` | `first_factor_reauthentication`, with MFA purpose `reauthenticate` |
| `link`           | none                                                               |

It is offered to both the identity-level requirement (AUTH-3.6) and the tenant's (AUTH-2.12). It is an input to that
policy and never an automatic pass. Which factors combine, including the first factor's channel, remains `laravel-mfa`'s
or the application's (AUTH-3.12).

## Success Path

- A `sign_in` of a linked subject, with an authentication time within the bounds and a combination satisfied, is
  admitted with `AcceptedEvidence`, which the adapter writes with the session in the same transaction.
- A reserved `sign_in` is activated and then judged, so the evidence is of the identity just established.
- A `reauthenticate` renews the session's authentication time and offers what this authentication gave.
- A connection's policy changed between completion and redemption decides that redemption.

## Failure / Edge Cases

- No authentication time, one older than the policy's `max_age_seconds` or the ceiling, whichever is lower now, or one
  later than the instant by more than `sso.clock.skew_seconds`, is `null`. Each bound is itself accepted, to the
  microsecond.
- A provider whose methods include an unlisted value still gives the listed ones: only they enter, and only they satisfy
  a combination. A provider-specific `amr` does not force class-only evidence, since a result may also carry accepted
  standard methods; a result with no accepted combination is insufficient. Accepted lists alone authorise nothing: a
  combination must name what counts.
- The raw `acr` or `AuthnContextClassRef` stays data, through `rawContext()`, so downstream policy cannot mistake it for
  an accepted class.
- `reauthenticate` with insufficient evidence still renews the authentication time, which is the purpose's whole
  meaning, and offers nothing.
- An error from the policy, or from a contract it reads, rolls the redeemer's transaction back with the code unconsumed.
  A configuration out of its bounds is such an error, not insufficient evidence.
- A JSON scalar in the column breaks `Connection::getEvidencePolicy()`'s return type; `ConnectionEvidencePolicy` reads
  that as a malformed policy.
- A `set()` is judged for the protocol of the row it locked; an unavailable protocol is `protocol_unavailable`.

## Implementation Anchors

- `src/Contracts/EvidencePolicy.php`, `src/Evidence/InsufficientEvidence.php`, `ConnectionEvidencePolicy.php`,
  `EvidenceRules.php`, `AcceptedEvidence.php`.
- `src/Connections/EvidenceSettingsService.php`.
- `src/Handoffs/Redemption/SignInBranch.php`, `ReauthenticationBranch.php`, `src/Handoffs/RedemptionResult.php`.
- `src/Protocols/Oidc/ClaimsAssembler.php`, `src/Protocols/Saml2/Validation/AuthenticationRules.php`,
  `src/Results/AuthenticationContext.php`.

## Authoritative Tests

- `tests/Feature/Linking/EvidenceAtRedemptionTest.php`: every clause through completion and redemption, on both
  protocols.
- `tests/Feature/Linking/EvidencePolicyTest.php`: the contract, its bound arguments and where a context comes from.
- `tests/Feature/Linking/EvidenceSettingsServiceTest.php`, `tests/Feature/Linking/SignInBranchTest.php`.
- `tests/Unit/Evidence/AcceptedEvidenceTest.php`, `tests/Unit/Evidence/EvidenceRulesTest.php`.

## Change Triggers

- What may stand in a policy, or how a combination is satisfied.
- A new source of authentication context, which must remain the validated assertion.
- A purpose that offers evidence, or a proof the mapping names.
- Anything `AcceptedEvidence` holds or shows.
