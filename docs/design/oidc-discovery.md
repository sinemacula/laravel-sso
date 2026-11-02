# OIDC Discovery And JWKS

## Purpose

This note records how an OpenID Connect connection is filled in from its issuer's discovery document, how it is kept up
to date from it, and how its JWKS is refetched when an ID token names a key it does not hold (SSO-2.8, SSO-2.9,
SSO-2.13, SSO-7.3, SSO-10.3, SSO-11.12): the strict reader of the document, the import that proposes settings, the trust
reset an update of the issuer or JWKS URI makes, the unknown-`kid` refetch and its cooldown, and the OIDC source of the
shared refresh machinery. The machinery itself (the claim and its token, the backoff, the queue, the command, the
compare and set) is `metadata-refresh.md`; the driver around it is `oidc-driver.md`; the JOSE adapter, which admits keys
and selects among them, is `jose-adapter.md`.

## Invariants

- `Metadata\DiscoveryDocument` reads a body within `sso.oidc.max_discovery_bytes` through `StrictJson`: a non-object, or
  a member repeated at any depth with its name read after unescaping, is `discovery_invalid`. `issuer` must be a string
  exactly equal to the one expected, byte for byte, so case, a trailing slash and the path all matter; anything else is
  `issuer_mismatch`, judged before the other members. `authorization_endpoint`, `token_endpoint` and `jwks_uri` are
  required, and `userinfo_endpoint` optional, each `SettingRules::url()`; `response_types_supported` is a list of
  strings holding `code`; `subject_types_supported`, when present, a list of strings;
  `code_challenge_methods_supported`, when present, a list of strings holding `S256`;
  `id_token_signing_alg_values_supported` a list of strings holding at least one of `AlgorithmAllowList::ALGORITHMS`;
  `token_endpoint_auth_methods_supported`, when present, a list of strings;
  `authorization_response_iss_parameter_supported`, when present, a boolean. Anything else is `discovery_invalid`, and a
  member it does not name is ignored. What it read came from whoever serves the issuer's URL, so it is held in a
  `\SensitiveParameterValue`: a dump and `json_encode()` show the names, and it refuses to be serialised.
- The document is found at the issuer with any trailing `/` removed and `/.well-known/openid-configuration` appended,
  path included (OpenID Connect Discovery §4), never by RFC 8414's insertion. Every fetch goes through the fetcher as a
  `discovery` or `jwks` request held to its own cap (SSO-2.9), with no credential. A refused or failed fetch is
  `fetch_refused` or `fetch_failed`, a response not `2xx` or over the cap included.
- `Metadata\DiscoveryImporter::import()` follows one order: `LogicException` inside a transaction on the storage
  connection; `protocol_unavailable` while `sso.features.oidc` is off; `settings_invalid` for an issuer that is not a
  valid setting; `connection_not_found` unless a connection named is the tenant's OIDC connection, read on the write
  connection; `rate_limited` past `AttemptSubject::metadata()`, counted before anything is fetched and only when a
  connection is named. It then fetches and validates (`fetch()`, shared with a refresh): the document, then the JWKS at
  its `jwks_uri`, read by `ProviderKeySet::read()` under the caps and the connection's allow-list or, with none named,
  the document's own algorithms in the package's order. A JWKS refused is `jwks_invalid`.
- An import writes nothing, trusts nothing, reports no event and logs nothing. `DiscoveryImport` is `proposed`,
  `refused` or `rateLimited`. `ProposedOidcSettings` holds `issuer`, the endpoints, `returns_iss` (true exactly when the
  document advertises `authorization_response_iss_parameter_supported` true), `id_token_algorithms` (the document's that
  are on the package's list, in the package's order), the client authentication methods it lists, and each admitted
  key's `kid`, `kty` and `alg`. No other member of a key and no secret. Nothing is trusted until it is saved through
  `ConnectionService::update()` with freshness.
- An update of an OIDC connection's `issuer` or `jwks_uri` also clears, in the same locked save as the change
  (`ProviderKeys::resetFor()`), `jwks`, `jwks_fetched_at`, `jwks_refetch_at` and `jwks_claim_token`, and raises
  `jwks_version` by one; of the `issuer`, also `metadata_fetched_at`, `metadata_valid_until` and `metadata_refresh_at`.
  Nothing else is set. The trust change voids what is in flight and raises the trust version as any other does. Keys
  fetched for another issuer or URL are therefore never used, and the first ID token after the change refetches at once.
- `ProviderKeys::select()` reads the stored JWKS on the write connection and selects with
  `ProviderKeySet::fromStored()->select()`. Only a selection that is `UNKNOWN` calls `JwksRefetcher`, once, and selects
  again from what it leaves stored; a `REFUSED` one (`none`, an HMAC, an algorithm off the allow-list, two admissible
  keys with no `kid`) never fetches. A select never refetches twice and never loops. An unknown supplied `kid` never
  falls back to a key without one, even after a refetch; a token with no `kid` and no admissible key is `UNKNOWN`.
- `JwksRefetcher::refetch()` refuses to run inside a transaction on the storage connection. It claims the cooldown,
  before it fetches, with one conditional update: where the id matches, `jwks_version` is the one read and
  `jwks_refetch_at` is unset or not after now, it sets `jwks_refetch_at` to now plus
  `sso.oidc.jwks_refetch_cooldown_seconds` and `jwks_claim_token` to a fresh random 128-bit token. No row updated means
  no fetch: the stored keys are read again and answered, `cooling_down`.
- Claimed, it fetches the `jwks_uri` it read, outside any transaction, noting the moment it validated. It then writes in
  one transaction on the storage connection whose first statement locks the connection's row; the lock order is the
  connection alone. Compare and set, for a success and a failure alike: `jwks_claim_token` equals its token, compared in
  constant time, and `jwks_version`, `trust_version`, the `issuer` and the `jwks_uri` equal what it read. A mismatch
  writes nothing, answers the winner's keys from the locked row with no other fetch, and reports `JwksRefreshFailed`
  with `metadata_conflict` and the locked `jwks_refetch_at`. When the connection is gone or its trust version has been
  raised and the winner's keys hold none for the token, `ProviderKeys` answers `overtaken`, which the completion refuses
  with `connection_unavailable` rather than `signature_invalid`.
- A success replaces the keys exactly, never as a union: `jwks`, `jwks_version` plus one, `jwks_fetched_at` the
  validated moment, `jwks_claim_token` cleared, `jwks_refetch_at` kept, so the cooldown stays. `changesFrom()` compares
  each key's whole stored form: a key removed, or replaced under the same `kid`, is `removed` and calls
  `InFlightVoider::voidFor()` once, which raises the trust version and voids in-flight requests and handoff codes, the
  request whose completion asked included. Keys added alone void nothing and leave the trust version as it was, so a
  refetch never voids its own callback. It reports `JwksRefreshed`.
- A failure (`fetch_refused`, `fetch_failed`, `jwks_invalid`) writes, under the same lock and compare and set, only
  `jwks_claim_token` cleared: the cooldown and the last good keys are kept, and it reports `JwksRefreshFailed`. A failed
  fetch therefore consumes the cooldown, so a provider that is down cannot be hammered by a flood of tokens.
- `Metadata\OidcMetadataSource` is the OIDC `MetadataSource`. It refreshes while the connection is OIDC,
  `metadata_refresh` is exactly `true` and the `issuer` passes the issuer URL rule. Its snapshot, the claim's and under
  the lock alike, is the JWKS version and the `issuer`, the endpoints, `returns_iss`, `id_token_algorithms` and
  `fetch_userinfo`, in a fixed order, read from the row, so it costs no query. It fetches as an import does, pinned to
  the saved issuer, under the connection's own allow-list. An allow-list that cannot be built from what is stored is
  contained: `settings_invalid`, logged by the exception's class alone, so a run goes on to the next connection.
- Under the lock (`RefreshWriter::locked()`), a document whose endpoint would not be a valid setting, or with no
  `userinfo_endpoint` while `fetch_userinfo` is on, is `discovery_invalid`. A document or JWKS validated a stale limit
  or longer before the commit is `metadata_expired` (`MetadataExpiry::hasExpired()`), each from its own moment. Either
  records a failure and keeps the last good settings and keys.
- A refresh may change only `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `userinfo_endpoint` (set or changed,
  never removed) and `returns_iss` (false to true only), and replaces the JWKS exactly. It never writes the issuer, the
  client id or authentication, a secret, the scopes, the algorithms, the mapping, what a subject means or enforcement.
  Any of those settings changing, or a key removed or replaced under the same `kid`, calls `voidFor()` exactly once.
  Additions alone void nothing and leave the trust version as it was.
- `metadata_fetched_at` is the moment the document validated and `jwks_fetched_at` the moment the JWKS did, each carried
  into the commit, so the 30-day stale limit counts from each resource's own validated fetch. A refetch stamps
  `jwks_fetched_at` too. `MetadataExpiry` applies to the document once a refresh has written it, and to the JWKS once a
  refresh has written the connection or while its `metadata_refresh` setting is on. So keys a refetch stamped on a
  connection whose refresh is on but has never succeeded, or has failed since an issuer change, age out too. A
  connection with its refresh off, whose keys only a refetch ever touches, stays exempt: a known `kid` never refetches,
  so it could not recover.
- Events, in order: an import none; a refresh adding keys `[MetadataRefreshed]`; one changing a setting and removing a
  key `[ConnectionUpdated, MetadataRefreshed]`, naming the settings in `OidcSetting` order then `jwks`; a failure or a
  conflict `[MetadataRefreshFailed]`, a conflict with the winner's failures and next attempt; a refetch
  `[JwksRefreshed]`, or `[JwksRefreshFailed]` when it failed or lost. Each is dispatched after the transaction commits,
  never on a rollback. None holds a key, a URL, a body or a token.
- `ProviderKeys` logs each refetch as `sso.oidc.jwks_refetch_refreshed`, `_cooling_down`, `_failed` or `_conflict` with
  its reason and the fetch's status alone, through the sanitising logger; the last two are warnings. `JwksRefetcher`
  answers how it ended and logs nothing, and `DiscoveryImporter` logs nothing. The refresher logs a refresh that did not
  apply, as it does for any source.
- Reads that decide a write are on the write connection (SSO-11.3); nothing depends on a cache (SSO-11.6); a database
  error propagates (SSO-11.4); none of these classes holds anything between calls (SSO-11.2).

## Success Path

1. An administrator imports the issuer, reviews the proposal, and saves it with `ConnectionService::update()`, with
   freshness, turning `metadata_refresh` on.
2. The first sign-in's ID token names a key the connection does not hold yet: the selection is unknown, the cooldown is
   claimed, the JWKS is fetched and stored, and the second selection finds the key. Nothing is voided.
3. The schedule queues a refresh of the connection, due a day after its last: the document and the JWKS are fetched and
   validated outside any transaction, and written under the lock. The next due date is a day on.
4. The provider publishes its next key: the refresh adds it and voids nothing. Later it stops publishing the old one:
   the refresh removes it, voids what is in flight and raises the trust version, once.

## Failure / Edge Cases

- A hundred tokens with unknown `kid`s arrive at once: one claim, one fetch, the rest answered from what is stored. The
  next refetch may start exactly at `jwks_refetch_at`, not a second before.
- Two servers hit the same unknown `kid`: one claims and fetches. The other, if the winner has written, rereads and
  finds the key; if it is still fetching, it answers what is stored, the token is refused, and the next attempt finds
  the key.
- An administrator changes the JWKS URI or the client secret while a refetch fetches: the refetch loses its compare and
  set and writes nothing. A PostgreSQL `REPEATABLE READ` transaction that read the connection before the claim fails to
  serialise instead (SQLSTATE 40001), changes nothing, and the refetch writes.
- A refetch and a refresh race: `jwks_version` lets exactly one write. A refetch that lost rereads the winner's keys; a
  refresh that lost is `metadata_conflict`.
- A refresh outlives its claim, and another server takes it over: the first writes nothing, success or failure.
- A document naming another issuer is `issuer_mismatch`: a refresh never changes the issuer, and an administrator who
  means to does so through `update()`, or a subject migration when the connection has links.
- A provider stops advertising the UserInfo endpoint: it stays stored; a connection that fetches UserInfo fails the
  refresh with `discovery_invalid` rather than silently losing it.
- A provider stops advertising `authorization_response_iss_parameter_supported`: `returns_iss` stays true, since a
  downgrade would remove a mix-up defence on the word of a document.
- The refresh or the provider is down for longer than the stale limit: starts and completions are `metadata_expired`
  until a refresh succeeds. A refetch cannot recover it, since the driver refuses before the keys are read. The expired
  last good keys stay stored for diagnosis.
- `sso.features.oidc` is off: nothing refreshes (`MetadataRefresher` asks `ProtocolManager::isAvailable()`), the
  schedule lists none of its connections, a queued refresh is `skipped` and an administrator's is `feature_disabled`, as
  an import is `protocol_unavailable`.
- A database error propagates and stops a scheduled run; the command reports the exception's class alone.

## Implementation Anchors

- `src/Metadata/DiscoveryDocument.php`, `DiscoveryImporter.php`, `DiscoveryImport.php`, `ProposedOidcSettings.php`,
  `OidcMetadata.php`.
- `src/Metadata/ProviderKeys.php`, `JwksRefetcher.php`, `OidcMetadataSource.php`.
- `src/Connections/ConnectionService.php` (`changeLocked()`, the trust reset).
- `src/Protocols/Oidc/Jose/StrictJson.php`, `ProviderKeySet.php`, `ProviderKey.php`, `AlgorithmAllowList.php`.
- `src/Metadata/RefreshClaims.php`, `RefreshWriter.php`, `MetadataExpiry.php`, `src/Connections/InFlightVoider.php`.
- `src/Administration/JwksEvents.php`, `src/Events/JwksRefreshed.php`, `JwksRefreshFailed.php`.

## Authoritative Tests

- `tests/Feature/Metadata/DiscoveryDocumentTest.php`: every rule at its boundary, the cap, duplicate members.
- `tests/Feature/Metadata/DiscoveryImporterTest.php`: the public import against hostile documents and JWKS, with the
  caps at, under and over.
- `tests/Feature/Metadata/OidcMetadataSourceTest.php`: what a refresh may change, when it voids, the refusals under the
  lock, the stale limit at commit, the compare and set.
- `tests/Feature/Metadata/ProviderKeysTest.php`, `JwksRefetcherTest.php`: which selections refetch, the cooldown to the
  second, replacement, voiding and the compare and set.
- `tests/Feature/Metadata/OidcRefreshEventSequenceTest.php`: each sequence with its full context, after commit, none on
  a rollback, and a scan of events, logs and results.
- `tests/Feature/Connections/OidcTrustResetTest.php`: exactly what an update clears.
- `tests/Integration/Metadata/ConcurrentJwksRefetchTest.php`, `ConcurrentOidcRefreshTest.php` (MySQL and PostgreSQL).
- `tests/Performance/OidcRefreshQueryBudgetTest.php`.

## Change Triggers

- A change to what the reader accepts, to how the document is found, or to what an import proposes.
- A change to which selections refetch, to the claim's conditions, or to what its compare and set compares.
- A change to what a refresh may write, to when a refresh or refetch voids and raises the trust version, or to its
  events and logs.
- A change to what an update of the issuer or JWKS URI clears.
- A change to the shared machinery's claim, compare and set, backoff or stale limit (`metadata-refresh.md`).
