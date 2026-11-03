# OIDC Driver

## Purpose

This note records the `oidc` protocol driver as a whole (SSO-2.2, SSO-2.4, SSO-5.4, SSO-5.9, SSO-7): what each of its
calls does and which collaborator does it, the values they hand each other, where a connection's JWKS and refresh state
are kept, the limits every OIDC connection is held to, and how the driver plugs into the flow core without bypassing
consumption, the lock order or enforcement. The parts are recorded in their own notes: the JOSE adapter in
`jose-adapter.md` (and the library's choice in `jose-library.md`), discovery, the JWKS and their refresh in
`oidc-discovery.md`, the authorisation request in `oidc-requests.md`, the callback and the token request in
`oidc-callback.md`, the ID token in `oidc-id-tokens.md`, UserInfo and the verified claims in `oidc-claims.md`, and the
relying party's description in `oidc-relying-party.md`.

## Invariants

- `Protocols\Oidc\OidcDriver` implements `Contracts\ProtocolDriver`, registered under `oidc` while `sso.features.oidc`
  is on, and built by the protocol manager from the container. Every check of SSO-7 is always on; the settings choose
  only what the requirements leave to a connection (`OidcSettings`).
- Each call reads the connection's settings afresh into `OidcOptions` (every setting typed, defaults applied, no secret)
  and hands them to one collaborator:
  - `settings()`: `OidcSettings`, the validation of every OIDC setting: the issuer and endpoints, `returns_iss`, the
    client id and authentication, `client_assertion_algorithm` (`PS256`, `RS256` or `ES256`, none by default, each key
    then signing with its own default), the scopes, the ID token algorithm allow-list, the extra parameters,
    `trusted_audiences` (at most ten, none by default), `max_age` (0 to a week, none by default), `fetch_userinfo`
    (off by default, the UserInfo endpoint then required) and `metadata_refresh` (on by default);
  - `isComplete()`: the settings are complete and the connection holds its client authentication's credential, a
    client secret for `client_secret_basic` and `client_secret_post` (`Connections\ConnectionSecrets::isSet()`) or, for
    `private_key_jwt`, a current `client_assertion` key (`Keys\KeyRing::current()`) that fits the pinned algorithm. An
    empty stored JWKS does not make a connection incomplete: the first ID token's unknown `kid` refetches it;
  - `start()`: `AuthorizationRequests`, the authorisation code request (`oidc-requests.md`);
  - `correlate()`: `CallbackCorrelator`, which reads the callback's raw query and validates nothing
    (`oidc-callback.md`);
  - `complete()`: `CallbackCompletion`, which checks the callback's `iss` and its code or error, sends the token request
    and answers a `Protocols\Oidc\Tokens\TokenResponse`, then asks `IdTokenValidator` for an `IdTokenValidation` and
    `ClaimsAssembler` for the `Protocols\Completion` (`oidc-callback.md`, `oidc-id-tokens.md`, `oidc-claims.md`);
  - `describe()`, `describeWithInlineKeys()` and `publicKeys()`: `RelyingPartyDescription` (`oidc-relying-party.md`).
- A connection's own key and its `client_assertion_algorithm` always fit: `ConnectionService` refuses a change of the
  setting that its current or next key cannot sign under, and `KeyService` a key that does not fit the setting, each
  under the connection's lock (`Keys\ClientAssertionKeys`). Changing the setting is a trust change like any other: it
  voids what is in flight and raises the trust version.
- `start()` and `complete()` are refused with `metadata_expired`, before their collaborator is asked, while anything
  fetched for the connection has expired (`Metadata\MetadataExpiry`): the discovery document from its last validated
  fetch (`metadata_fetched_at`) and the JWKS from its own (`jwks_fetched_at`), each plus the stale limit, whether or not
  its refresh is scheduled. Turning the schedule off never means unlimited trust; only an explicit limit of `0` does. A
  connection with nothing fetched yet, its keys and endpoints saved by hand, has no deadline. The completion checks
  expiry again on the locked connection (`completion.md`). An expired connection recovers through a scheduled refresh or
  an administrator's (`metadata-refresh.md`), never through a callback.
- The values the collaborators hand each other carry provider tokens and claims (SSO-7.6), so each holds them in a
  `\SensitiveParameterValue`, shows none of them in a dump or in JSON, and refuses to be serialised or unserialised:
  `TokenResponse` (the ID token and the access token, never a refresh token), `ValidatedIdToken` (the issuer, the
  subject and the claims of a token every check passed) and `IdTokenValidation` (validated, or refused with a reason).
- Every call to `web-token/jwt-library` is made inside the adapter's namespace (`Protocols\Oidc\Jose`), by
  `JoseAdapter` alone; the driver and its collaborators read only the package's own values (`jose-adapter.md`). A
  protocol driver never reads a connection's row (`NamespaceDependenciesTest`), so the JWKS stored with a connection is
  read by `Metadata\ProviderKeys`, beside the refresh machinery that writes it, and a secret through
  `ConnectionSecrets::revealFor()`.
- A connection's JWKS is kept on its row (`jwks`, a JSON list of the public members of each admitted key, at most
  `sso.oidc.max_jwks_keys`), with `jwks_version` (raised by every write of it, so a refetch and a refresh compare and
  set), `jwks_fetched_at` (its last validated fetch), `jwks_refetch_at` (no unknown-`kid` refetch starts before it: the
  cooldown) and `jwks_claim_token` (the token of the refetch in progress). The discovery document's refresh state is
  the row's `metadata_*` columns, shared with SAML.
- The scheduled and administrator's refresh of the discovery document and the JWKS runs through the shared refresh
  machinery (`metadata-refresh.md`): `Metadata\OidcMetadataSource` is the OIDC `Metadata\MetadataSource`, so the claim
  and its token, the backoff, the queued job, the command, the compare and set (`Metadata\RefreshWriter`), the stale
  limit and `MetadataRefreshed` and `MetadataRefreshFailed` are SAML's. The refetch of the JWKS on an unknown `kid` is
  its own operation and reports `JwksRefreshed` and `JwksRefreshFailed` (`Administration\JwksEvents`).
- The limits are `sso.oidc` (`OidcLimits`, checked at boot by `[oidc]` while the feature is on): the ID token, the
  JWKS (size and keys), the discovery document, the token and UserInfo responses (each held as the request's own cap),
  the callback's parameters (each, the whole query, how many), the refetch cooldown, the ID token's maximum age, and
  the token and UserInfo timeouts (each the request's own, in place of the fetcher's).
- The driver never consumes, locks, records or writes, but for the JWKS refetch's own claim and compare-and-set write
  outside the completion's transactions. The flow core does the rest, in its fixed order (`completion.md`): the
  driver's `correlate()` outside any transaction; the request found by its state's digest and consumed in a
  transaction of its own, the connection's row locked before the request's, a request whose stored trust version is
  not the locked connection's refused `connection_unavailable` there, so no provider is called for a flow a trust
  change overtook; the driver's `complete()` against the consumed request outside any transaction (the token request,
  any JWKS refetch and the UserInfo request among it); then one transaction in the global lock order that refuses a
  connection no longer usable or a request voided or no longer of the locked trust version, and resolves the link,
  judges enforcement and issues the handoff code.
- A key rotation the callback's own unknown-`kid` refetch finds lets that one sign-in finish. When the refetch commits a
  change that is only of the JWKS and that removes a key, it raises the trust version and voids every other request and
  every issued handoff code as any trust change does, and answers a `Protocols\TransitionReceipt` naming the connection,
  the old and new trust versions, the JWKS version it wrote and the consumed request whose token asked. The voiding and
  the receipt are one transaction: that request alone is spared, by a locking read that finds it consumed, unfinished,
  unvoided and of the locked trust version, so a request something else voided is never restored. The receipt lives
  only in that completion's memory, is never stored and refuses to be serialised. The flow carries it on only once the
  whole token has passed every check under the new keys, and UserInfo when fetched. At the final locks
  (`Metadata\TransitionReceipts`) the request goes on only across that exact transition: both trust versions and the
  JWKS version as named, the verifying key still admitted for the algorithm it verified under, and the metadata fresh
  (`metadata_expired` otherwise). Anything independent since (a second trust change, a distrust, a disable, a delete, a
  further write of the keys) refuses it, and a later trust version is never simply adopted. A key added alone voids
  nothing and needs no receipt.
- A completion and a start each refuse to run inside a transaction already open on the storage connection
  (`StorageConnection::assertNoTransaction()`), so the token request and every other provider call is never made
  inside one.
- The driver and its collaborators are kept by the protocol manager for one scope, a request's sandbox or a job, so
  none holds connection, flow or result state between calls (SSO-11.2).

## Success Path

1. An administrator imports the issuer's discovery document, saves the settings and the client secret (or adds a
   `client_assertion` key and registers its public JWKS), and enables the connection.
2. A start builds the authorisation request and stores the request with the issuer and whether it must return `iss`.
3. The callback is correlated by its `state`, its request consumed, its `iss` and code checked, the code exchanged, the
   ID token validated against the stored JWKS (refetched once on an unknown `kid`), UserInfo read when the connection
   fetches it, and the verified claims built.
4. Under the locks, the link is resolved, enforcement judged and the handoff code issued.

## Failure / Edge Cases

- A connection whose discovery document or JWKS was validated longer ago than the stale limit: every start and
  completion is `metadata_expired` until a scheduled or administrator's refresh succeeds, with its schedule off too. A
  callback cannot recover it: the driver refuses before the keys are ever read, so no refetch is reached.
- A callback's refetch that removes a key while another change lands before the final locks: its token verifies, and
  the completion is refused `connection_unavailable` with no code.
- A database error, a misconfiguration and an exception a collaborator throws propagate (SSO-11.4).

## Implementation Anchors

- `src/Protocols/Oidc/OidcDriver.php`, `OidcOptions.php`, `OidcSettings.php`, `Enums/OidcSetting.php`,
  `OidcLimits.php`, `OidcCheck.php`.
- `src/Protocols/Oidc/AuthorizationRequests.php`, `CallbackCorrelator.php`, `CallbackCompletion.php`,
  `IdTokenValidator.php`, `ClaimsAssembler.php`, `RelyingPartyDescription.php`.
- `src/Protocols/Oidc/Tokens/TokenResponse.php`, `ValidatedIdToken.php`, `IdTokenValidation.php`.
- `src/Protocols/Oidc/ClientAssertionAlgorithm.php`, `src/Keys/ClientAssertionKeys.php`.
- `src/Protocols/TransitionReceipt.php`, `src/Metadata/TransitionReceipts.php`, `src/Metadata/JwksRefetcher.php`.
- `src/Protocols/Oidc/Jose/` (the adapter), `src/Metadata/ProviderKeys.php`, `src/Metadata/OidcMetadataSource.php`.
- `src/Events/JwksRefreshed.php`, `JwksRefreshFailed.php`, `src/Administration/JwksEvents.php`.
- `database/migrations/2026_11_01_000000_create_sso_connections_table.php` (the JWKS columns).
- `src/Testing/FakeOpenIdProvider.php`, `src/Testing/Oidc/` (the fake provider and the hostile tokens).

## Authoritative Tests

- `tests/Feature/Protocols/Oidc/OidcDriverTest.php`: the driver from the container, completeness by client
  authentication, expiry of the discovery document and the JWKS, and each call reaching its collaborator.
- `tests/Feature/Protocols/Oidc/OidcSettingsTest.php`, `OidcLimitsTest.php`, `tests/Unit/Protocols/Oidc/`.
- `tests/Feature/Metadata/ProviderKeysTest.php`, `MetadataSourcesTest.php`, `MetadataExpiryTest.php`,
  `TransitionReceiptsTest.php`.
- `tests/Feature/Completion/OidcKeyRotationCompletionTest.php`,
  `tests/Integration/Completion/OidcKeyRotationRaceTest.php`: the same-step rotation, every other flow voided, and what
  refuses the trigger.
- `tests/Feature/Connections/ClientAssertionAlgorithmTest.php`: a key and an algorithm that do not fit, refused
  whichever changes.
- `tests/Unit/Testing/FakeOpenIdProviderTest.php`, `tests/Unit/Testing/Oidc/`.

## Change Triggers

- A new collaborator, or a call moving to another.
- A change to the values the collaborators hand each other, or to what they hold.
- A change to where the JWKS or the refresh state is kept, or to the limits.
- A change to how the driver plugs into the flow core, or to what it reads or writes.
