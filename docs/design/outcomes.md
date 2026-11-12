# Outcomes and Throttling

## Purpose

This note records how the package's contracts and helpers answer: which outcomes are values, what `null` and `bool`
may mean, what shape a result takes, how throttling is answered, and what an exception means. It is the convention of
`laravel-authentication`'s outcomes, kept so the suite reads as one codebase; each operation keeps its own type, and
the convention is the shape.

## Invariants

- Expected refusals are values. A refusal of untrusted input (a response, a callback, a code, a verifier) or of
  policy (a disabled connection, an application that does not allow external sign-in, throttling) is returned, never
  thrown. Exceptions mean a misconfiguration, an invalid argument from application code (`InvalidArgumentException`,
  `LogicException`) or a server error (a database error, a store that cannot answer), which propagates (SSO-11.4).
- A result object answers when success carries a payload or the operation can be throttled. It is `final readonly`,
  built only through named constructors (one per outcome), says which outcome it is through `is...()` predicates,
  carries its payload in nullable public properties set only for the outcome that has it, names a refusal by `reason`
  (`Events\Enums\FailureReason`), and carries `retryAfter` when it can be throttled. A result with more than two
  outcomes exposes `status`, a string-backed enum naming every outcome, success included.
- An outcome enum answers when success carries nothing and nothing throttles. It is string-backed and names its success
  case, so matching on the enum tells success from refusal.
- `null` means only "nothing to act on", never success or refusal; `bool` and `int` only for what an idempotent call
  changed. No union of a success type with a failure type.
- Throttling is an outcome: `rate_limited`, with `retryAfter`.
- A value that carries a secret (a credential, a token request's form, a response body) keeps it private, masks it
  in a dump and refuses to be serialised or unserialised, so it cannot reach a log, an exception, a queue or an event.

## Success Path

- `Contracts\Clock::now()` answers a `CarbonImmutable`.
- `Contracts\SingleUseStore::record()` answers `SingleUse\Enums\SingleUseOutcome`: `recorded` (success, the only answer
  that lets a flow proceed) or `seen`. A store that cannot tell throws.
- `Contracts\Fetcher::fetch()` takes a `Fetching\FetchRequest` (built per purpose, with the one credential that purpose
  may carry, `Fetching\FetchCredentials`) and answers a `Fetching\FetchResult`: `fetched` with the HTTP status code,
  headers and body (`isSuccessful()` for a `2xx`), `refused` (`fetch_refused`) or `failed` (`fetch_failed`), status
  `Fetching\Enums\FetchStatus`.
- `Contracts\AttemptLimiter::attempt()` takes a `RateLimiting\AttemptSubject` (built per flow) and answers a
  `RateLimiting\AttemptResult`: allowed, or `rate_limited` with `retryAfter` of at least one second.
- `Contracts\SecretEncrypter` answers strings; a ciphertext that cannot be decrypted is a server error, thrown.

### Management helpers (SSO-2.11, SSO-2.12)

The helpers that change connections, keys and certificates follow one shape, so an administration screen handles them
the same way:

- Every helper is scoped to a tenant: it takes the tenant's opaque id and the connection's id, and a connection of
  another tenant is answered exactly as an unknown one, `connection_not_found`.
- A change answers a result object (`final readonly`, named constructors, `is...()` predicates) carrying, on success,
  the summary of what it changed (a connection's summary, or a key's `Keys\KeySummary`), and on refusal a `reason` from
  the administration group of `FailureReason`: `freshness_required` (the freshness contract answered `stale`),
  `connection_not_found`, `key_not_found`, `settings_invalid` (with `violations`, a list of
  `Connections\SettingViolation`, each naming a setting and a `Connections\Enums\ViolationCode`, never a value),
  `protocol_unavailable` and `key_state_conflict`.
- A change that changed nothing (enabling an enabled connection, an update that gives the stored values) succeeds and
  says so, writes nothing and reports nothing.
- The order is fixed: find the connection (and the key) on the write connection; validate what was given; ask the
  freshness contract with each operation the change is (`Freshness\FreshnessGate`); then write, in one transaction on
  the storage connection, and report through `Administration\AdministrationEvents` inside it. A refusal at any step
  writes nothing and dispatches nothing.
- A read answers `null` for a connection it did not find (`get()`), and a list, possibly empty, otherwise.
- The domain helpers (`Domains\DomainService`) answer a `Domains\DomainResult` the same way, with the domain
  reasons of `FailureReason` (`domain_not_found`, `domain_unavailable`, `domain_claim_expired`,
  `domain_record_not_found`, `domain_lookup_failed`), and `rate_limited` with `retryAfter` for a verification; see
  `domains.md`. The enforcement helpers add `feature_disabled` and `completed_sign_in_required`; see
  `enforcement.md`.
- Disabling and deleting a connection (`Connections\ConnectionLifecycle`) and migrating its subjects
  (`Connections\SubjectMigration`) answer the same `Connections\ConnectionResult`, in the same order: `disabled` (or
  `unchanged` for a connection already disabled), `deleted` (with no summary, since the connection is gone) and
  `migrated`; a change that may alter what the connection's subjects mean while it has links is refused with
  `connection_has_links`, and a migration whose relinks and removals do not account for every current link exactly
  once with `links_unaccounted`; see `connection-lifecycle.md`.
- An application's mistake (an empty tenant id, a caller with an empty session id) is an `InvalidArgumentException`; a
  database error, a `SecretEncrypter` that cannot encrypt or a key OpenSSL cannot generate propagates.

### Flow, link, handoff and completion operations (SSO-5, SSO-8, SSO-9)

The operations a flow goes through answer the same way: a result object for each, with `status` wherever there are
more than two outcomes, a `reason` from `FailureReason` on every refusal, and `retryAfter` (at least one second)
wherever a limit can refuse. Each refusal of a start, a completion or a redemption reports exactly one `FlowFailed`
with the flow and the same reason; a link helper's refusal reports nothing.

- Starting a flow. `Flows\AuthorizationRequestService::start()` and `Discovery\DiscoveryService::start()` answer a
  `Flows\StartResult`, status `Flows\Enums\StartStatus`: `started` (the reference, the navigation, and the verifier
  the package generated, revealed once in `body()`), `refused` (`reason`) or `rate_limited` (`retryAfter`). Every
  answer's `headers()` carry `Cache-Control: no-store`, and a rate limited one `Retry-After`. The order is fixed:
  the binding (a misbound purpose is an `InvalidArgumentException`), the rate limit (`rate_limited`), the application
  (`application_not_allowed`), the challenge (`challenge_invalid`), the connection (`connection_unavailable`), then
  the freshness of a `link` (`freshness_required`) and the session of a `reauthenticate` (`session_ineligible`), and
  last the driver, whose refusal keeps its own reason. Discovery checks that the application offers it
  (`feature_disabled`) before the challenge, and answers a miss (`discovery_no_match`, reported) as `started`, in
  the same shape as a match. A start called inside a transaction open on the storage connection is a
  `LogicException`. See `authorization-requests.md`, `discovery.md` and `flows.md`.
- Consuming a request (`Flows\RequestConsumption`, `@internal`, the completion's only way to consume one) answers a
  `Flows\ConsumptionResult`, status `Flows\Enums\ConsumptionStatus`: `consumed`, `refused` (`application_not_allowed`,
  `request_unknown`, `connection_unavailable`, `connection_mismatch` or `request_expired`), `unknown` or `replayed`
  (both `request_unknown`).
- Completing a flow. `Completion\CompletionService` answers a `Completion\CompletionResult`, status
  `Completion\Enums\CompletionStatus`: `completed` (the redirect URI, the delivery, the reference and the issued
  handoff), `failed` (a refusal with a trusted redirect target: the reason, redirected to the application), `rejected`
  (a refusal with none: `request_unknown`, `connection_unavailable` or `application_not_allowed`, a 400), `rate_limited`
  (`retryAfter`, a 429) or `reinitiated` (SSO-5.8). A failure carries the reason of the step that refused: the
  consumption's above, a driver's (`signature_invalid`, `issuer_mismatch` and the other protocol reasons),
  `enforcement_unsatisfied`, the purpose's rules (`link_suspended`, `principal_scope_unknown`, `link_reserved`,
  `link_ineligible`, `subject_already_linked`, `identity_mismatch` and `authentication_expired`), `unlinked` and
  `application_not_allowed`. A listener's or a contract's exception is no refusal: it propagates, and the request stays
  consumed and unfinished. `Responses\CompletionResponses` turns it into the response value the application answers
  with. A completion called inside a transaction open on the storage connection is a `LogicException`. See
  `completion.md` and `completion-responses.md`.
- Redeeming a handoff. `Handoffs\HandoffRedemption::admit()`, the session-admission path, which needs the caller's
  open transaction on the storage connection, and `redeem()`, standalone only for a `link`, answer a
  `Handoffs\RedemptionResult`, status `Handoffs\Enums\RedemptionStatus`: `redeemed` (the verified result and what the
  code was bound to), `refused` (`handoff_unknown`, `replayed`, `handoff_expired`, `purpose_mismatch`,
  `application_mismatch`, `connection_mismatch`, `verifier_mismatch`, `connection_unavailable`,
  `enforcement_unsatisfied`, `link_changed`, or the purpose's refusals below) or `rate_limited` (`retryAfter`).
  `Handoffs\HandoffRecheck::recheck()`, for an adapter's own redemption under the `Handoffs\RecheckLock` its `lock()`
  took first, answers the outcome enum `Handoffs\Enums\RecheckOutcome` (`passed` or the first refusal), whose `reason()`
  names the `FailureReason` a refused redemption reports. Beyond the checks of every redemption, those are
  `link_suspended`, `principal_scope_unknown`, `link_reserved`, `link_ineligible`,
  `independent_authentication_required`, `identity_mismatch`,
  `subject_already_linked`, `link_limit_reached`, `reservation_invalid`, `freshness_required`, `session_ineligible` and
  `authentication_expired`. `HandoffRecheck::admit()` makes the purpose's writes too and answers a
  `Handoffs\Redemption\Admission`: `isPassed()`, the outcome, the identity it established, the link it resolved
  through and any evidence accepted. `discardReservation()` and `acknowledgeSignIn()` answer nothing: each is a write
  inside the redeemer's transaction, and a call out of turn is a `LogicException`. See `handoffs.md` and `linking.md`.
- Links. `Links\LinkService::list()` answers a list of `Links\LinkSummary`, possibly empty; `remove()` answers a
  `Links\LinkResult`: `removed` (the summary) or `refused` (`link_not_found`, for another identity's link as for an
  unknown one, or `freshness_required`). `Links\LinkStore::create()` answers a `Links\LinkCreation`, status
  `Links\Enums\LinkCreationStatus`: `created` (the summary), `subject_already_linked` or `link_limit_reached`, each
  refusal naming that reason. `Contracts\Linker::resolve()` answers a `Links\LinkResolution`, status
  `Links\Enums\LinkResolutionStatus`: `linked` (the identity and the link's id), `absent`, `reserved`, `suspended` or
  `scope_unknown` (each of the last two with the holder and the link's id; `scope_unknown` when
  `Contracts\PrincipalScope` answered `unknown`, refusing this attempt and suspending nothing). `null` is no answer
  here, since a suspension or a reservation must never read as unlinked: only `absent` lets a result reserve, be
  provisioned or take an unlinked handoff. See `links.md` and `linking.md`.
- Provisioning. `Provisioning\ProvisioningHelper::link()`, called by a listener of `Events\ResultUnlinked` with the
  grant it was given, answers a `Provisioning\ProvisioningResult`, status `Provisioning\Enums\ProvisioningStatus`:
  `created` (the summary), `grant_invalid` and `grant_wrong_result` (`provisioning_grant_invalid`),
  `request_unavailable` (`connection_unavailable`), `expired` (`request_expired`), `subject_already_linked` or
  `link_limit_reached`, whose `reason()` names each refusal's reason. See `linking.md`.
- Issuing a handoff. `Contracts\HandoffIssuer::issue()` answers a `Handoffs\IssuedHandoff`: the code, revealed
  once, and its expiry. An issuer that cannot issue throws, and the completion propagates it.

## Failure / Edge Cases

- A failure reason is a stable code (`FailureReason`), never prose; the application words it (SSO-12.6). A failure
  redirect, a failure event and a refused result carry the same code.
- A fetch's detail (the host that did not resolve, the TLS error) goes to the logs only; the result carries the code.
- A database error is never turned into a refusal: it propagates, and the application answers it as a server error.

## Implementation Anchors

- `src/Events/Enums/FailureReason.php`; `src/SingleUse/Enums/SingleUseOutcome.php`.
- `src/Fetching/FetchRequest.php`, `src/Fetching/FetchCredentials.php`, `src/Fetching/FetchResult.php`,
  `src/Fetching/Enums/`.
- `src/RateLimiting/AttemptSubject.php`, `src/RateLimiting/AttemptResult.php`, `src/RateLimiting/Enums/`.
- `src/Contracts/`.
- `src/Connections/SettingViolation.php`, `src/Connections/Enums/ViolationCode.php`, `src/Freshness/FreshnessGate.php`,
  `src/Administration/AdministrationEvents.php`; the management helpers in `src/Connections/` and `src/Keys/`,
  `src/Connections/ConnectionLifecycle.php` and `src/Connections/SubjectMigration.php` among them.
- `src/Flows/StartResult.php`, `src/Flows/ConsumptionResult.php`, `src/Flows/Enums/`,
  `src/Flows/AuthorizationRequestService.php`, `src/Discovery/DiscoveryService.php`.
- `src/Completion/CompletionResult.php`, `src/Completion/Enums/CompletionStatus.php`,
  `src/Completion/CompletionService.php`, `src/Responses/`.
- `src/Handoffs/RedemptionResult.php`, `src/Handoffs/Enums/`, `src/Handoffs/HandoffRedemption.php`,
  `src/Handoffs/IssuedHandoff.php`.
- `src/Handoffs/Redemption/Admission.php`.
- `src/Links/LinkResult.php`, `src/Links/LinkCreation.php`, `src/Links/Enums/LinkCreationStatus.php`,
  `src/Links/LinkResolution.php`, `src/Links/Enums/LinkResolutionStatus.php`, `src/Links/LinkService.php`,
  `src/Links/LinkStore.php`.
- `src/Provisioning/ProvisioningHelper.php`, `src/Provisioning/ProvisioningResult.php`,
  `src/Provisioning/Enums/ProvisioningStatus.php`.

## Authoritative Tests

- `tests/Unit/Events/Enums/FailureReasonTest.php`, `tests/Unit/SingleUse/SingleUseOutcomeTest.php`.
- `tests/Unit/Fetching/FetchRequestTest.php`, `tests/Unit/Fetching/FetchCredentialsTest.php`,
  `tests/Unit/Fetching/FetchResultTest.php`.
- `tests/Unit/RateLimiting/AttemptSubjectTest.php`, `tests/Unit/RateLimiting/AttemptResultTest.php`.
- `tests/Unit/Connections/ConnectionResultTest.php`, `tests/Feature/Connections/ConnectionLifecycleTest.php`,
  `tests/Feature/Connections/SubjectMigrationTest.php`.
- `tests/Unit/Flows/StartResultTest.php`, `tests/Unit/Flows/ConsumptionResultTest.php`,
  `tests/Feature/Flows/AuthorizationRequestServiceTest.php`, `tests/Feature/Discovery/DiscoveryServiceTest.php`.
- `tests/Unit/Completion/CompletionResultTest.php`, `tests/Unit/Responses/CompletionResponseTest.php`,
  `tests/Feature/Completion/CompletionServiceTest.php`.
- `tests/Unit/Handoffs/RedemptionResultTest.php`, `tests/Unit/Handoffs/RecheckOutcomeTest.php`,
  `tests/Feature/Handoffs/HandoffRedemptionTest.php`.
- `tests/Unit/Links/LinkResultTest.php`, `tests/Unit/Links/LinkCreationTest.php`,
  `tests/Unit/Links/LinkResolutionTest.php`, `tests/Feature/Links/LinkServiceTest.php`,
  `tests/Feature/Links/LinkStoreTest.php`.
- `tests/Feature/Linking/ProvisioningTest.php`, `tests/Feature/Linking/LinkConfirmationTest.php`.

## Change Triggers

- A new public operation, or a change to what one returns.
- A new outcome of an existing operation, a new failure reason, or a refusal that becomes or stops being an exception.
