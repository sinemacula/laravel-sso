# Metadata Refresh

## Purpose

This note records how a SAML connection is filled in from its identity provider's metadata and kept up to date from
it (SSO-2.8, SSO-6.11, SSO-10.3, SSO-11.12): the metadata validation profile, the import that proposes settings, the
scheduled and on-demand refresh that applies certificates and endpoints, the claim and the compare-and-set that keep
racing servers and administrators from overwriting each other, the trust version, the backoff, and the expiry of what
a refresh applied. The SAML adapter it reads metadata through is in `saml-adapter.md`; the keys and anchors in
`keys.md`.

## Invariants

- Metadata is read only by `Protocols\Saml2\Library\MetadataReader`, inside the adapter's namespace, the only place
  the SAML library is called (`saml-adapter.md`). It answers a `Protocols\Saml2\Messages\IdpMetadata`, read
  or refused with a `FailureReason` and the rule's name; the values it holds are in a `\SensitiveParameterValue`,
  redacted from dumps and JSON, and it refuses to be serialised.
- The document is capped at `sso.fetcher.max_response_bytes` (read through `Fetching\FetcherSettings`), whether it was
  given as XML or fetched, and parsed by the hardened parser against the SAML 2.0 metadata schema: no document type, no
  entity, no network, no `ID` repeated. Anything else is `metadata_invalid`.
- The root is an `EntityDescriptor` or an `EntitiesDescriptor`. The entity is chosen by the pinned entity id alone,
  compared exactly: exactly one `EntityDescriptor` anywhere in the document carries it (none is
  `metadata_entity_not_found`, two `metadata_invalid`, wherever the second hides), and it is the root or a child of an
  `EntitiesDescriptor` that is itself the root or such a child, checked by walking its ancestors. An entity hidden in a
  signature's `Object`, an `Extensions` or anywhere else is refused. Within the entity, the only signature allowed is
  its own.
- With an anchor set (the connection's `metadata_signing` certificates, `Keys\KeyRing::trustedCertificates()`), the
  entity must be covered by a signature, its own or an enclosing `EntitiesDescriptor`'s, and every signature on that
  path must verify with an anchor through `PinnedVerifier`, each signed element copied into a document of its own first
  (`saml-library.md`, condition 3), with the same `SignedInfo` policy as a response. Unsigned metadata, metadata signed
  by a key no anchor holds, or a signature that does not cover the entity is `metadata_signature_invalid`. Without
  anchors no signature is read.
- The expiry of metadata is the earliest `validUntil` of the entity and every descriptor enclosing it; `cacheDuration`
  is ignored. Metadata whose `validUntil` is not after now is `metadata_expired`. Undated metadata is accepted.
- The entity must have exactly one `IDPSSODescriptor` supporting the SAML 2.0 protocol, with a single sign-on service
  of the HTTP-Redirect or HTTP-POST binding (the first of each; the connection's current binding preferred, then
  HTTP-Redirect) and at least one RSA signing certificate (a `KeyDescriptor` of use `signing` or none); otherwise
  `metadata_invalid`. Certificates the package cannot use (not RSA, under 2048 bits, unreadable) are ignored, and a
  certificate given twice is kept once, by its SHA-256 fingerprint, re-encoded as a canonical PEM. Encryption
  certificates (use `encryption` or none) and the NameID formats offered are read for the import only.
- An import (`Metadata\MetadataImporter`, `importXml()` and `importUrl()`) writes, trusts and reports nothing. It
  answers an `ImportResult`: `ProposedSettings` (`idp_entity_id`, `sso_url`, `sso_binding`, the signing and encryption
  certificates with their fingerprints, the NameID formats, the `validUntil`), a refusal, or `rate_limited`. While
  `sso.features.saml2` is off every import is `protocol_unavailable`, before any lookup, read or fetch. A connection
  named must be the tenant's SAML connection (otherwise `connection_not_found`); its anchors then apply. `importUrl()`
  counts the attempt against `AttemptSubject::metadata()` when a connection is named, before it fetches through the
  fetcher as a `metadata` request (SSO-2.9). A proposal that would not be valid settings (a single sign-on URL that is
  not `https`, an entity id that is neither a URL nor a URN) is `metadata_invalid`.
- A connection refreshes only while `sso.features.metadata_refresh` is on, it is a SAML connection, its
  `metadata_refresh` setting is on and its `metadata_url` is a valid `https` URL: the URL the administrator saved is the
  only one ever fetched. `refreshDue()` reads, on the write connection, the SAML connections whose
  `metadata_refresh_at` is unset or not after now and whose `metadata_claimed_until` is unset or not after now, in
  chunks of 100 by keyset on the id, and refreshes those that refresh. `refreshNow()` refreshes the tenant's connection
  whatever its backoff (`connection_not_found` for another tenant's, `feature_disabled` for one that does not refresh).
  Both refuse to run inside a transaction on the storage connection (`StorageConnection::assertNoTransaction()`).
- Each refresh reads the connection, then its anchors: that is the snapshot (metadata version, trust version, anchor
  fingerprints). It then claims the connection with one conditional update outside any transaction:
  `metadata_claimed_until = now + claim_seconds` where the id matches, no claim holds and the metadata version is the
  one read. No row updated is `skipped` (scheduled) or `in_progress` (`metadata_refresh_in_progress`, an
  administrator's), and nothing else happens: an administrator's refresh skips the backoff, never a claim.
- Outside any transaction, the claimed refresh fetches the saved URL and reads it with the pinned `idp_entity_id`, the
  anchors of the snapshot and the current binding. Only then does it write, in one transaction on the storage
  connection (`Metadata\MetadataApplier`), whose first statement locks the connection's row; the lock order is the
  connection alone. Every read that decides the write is a locking read: the connection, the anchors' fingerprints and
  the trusted certificates.
- Compare and set: the locked connection must have the snapshot's metadata version and trust version, and the anchors
  read under the lock must be the snapshot's. Otherwise the refresh is `conflict` (`metadata_conflict`) and writes
  nothing, not even its claim, which expires; `MetadataRefreshFailed` reports it with the failures and next attempt as
  the winner left them. Every trust change (a certificate removed, an anchor added or removed, the entity id, the
  endpoints, the metadata URL or switch, a disable) raises the trust version under the same lock, so a refresh based on
  the configuration before it never writes over it.
- Under the lock, metadata of an entity other than the locked `idp_entity_id`, or whose endpoint would not be a valid
  setting, is refused `metadata_invalid`, and metadata whose `validUntil` has passed by the clock read at commit is
  refused `metadata_expired`. Either records a failure.
- A refresh changes only the identity provider signing certificates and the single sign-on endpoint (`sso_url`,
  `sso_binding`); never the entity id, the subject settings, the mapping or enforcement. The certificates are replaced
  exactly, never as a union (`Keys\KeyService::replaceTrustedCertificatesLocked()`): one no longer published is
  distrusted and reported `KeyRetired`, one newly published trusted as `idp_signing` and reported `KeyAdded`, with the
  same judgement as `trustCertificate()` (RSA, not twice, at most ten). The identity provider's encryption certificates
  are never stored: the package encrypts nothing to an identity provider.
- The trust version follows the existing rules. A refresh that only adds certificates voids nothing and leaves it as it
  was, so a provider publishing its next key never voids its own flows. Any removal, replacement or endpoint change
  voids the requests and handoff codes in flight through the connection and raises the trust version, once
  (`Connections\InFlightVoider::voidFor()`); an endpoint change is reported `ConnectionUpdated` naming the settings.
- A successful refresh raises `metadata_version`, sets `metadata_fetched_at` to now, `metadata_valid_until` to the
  metadata's `validUntil`, `metadata_refresh_at` to now plus `refresh_interval_seconds` (never after the `validUntil`),
  resets `metadata_refresh_failures` and releases the claim; `MetadataRefreshed` names the settings changed (`sso_url`,
  `sso_binding`, in that order, then `idp_signing_certificates`), none when nothing did, with the metadata version and
  whether the trust changed.
- A failed refresh (a fetch refused or failed, a response not `2xx`, metadata refused, or a refusal under the lock)
  writes, under the lock and while no other refresh has written: `metadata_refresh_failures` plus one,
  `metadata_refresh_at` at now plus `MetadataSettings::backoffSeconds()` for that many (5 minutes, doubling, at most 6
  hours by default), the claim released; the last good settings are kept. `MetadataRefreshFailed` carries the reason,
  the failures and the next attempt; the refresher logs the reason and the fetch's status alone, through the sanitising
  logger, never the URL, the response or the metadata.
- What a refresh applied expires (`Metadata\MetadataExpiry`, which the driver checks before every start, completion and
  re-initiation, and the completion and the re-initiation check again on the locked connection, failing with
  `metadata_expired`) at the earlier of `metadata_valid_until` and `metadata_fetched_at` plus
  `sso.metadata.stale_limit_seconds` (30 days by default; `0`, set explicitly, for no limit). The expired last good
  settings stay stored, for diagnosis, until a refresh succeeds.
- Events (`Administration\MetadataEvents`) are built through the one context projection, with the acting identity of
  the administrator who asked or none for a scheduled run, and dispatched after the transaction commits, never on a
  rollback. None holds a certificate, a URL or any value of the metadata.
- A refresh asks no freshness: it is a system job that the administrator switched on, with freshness, by saving
  `metadata_refresh` and `metadata_url`, and an administrator's refresh does no more than the schedule would.

## Success Path

1. An administrator imports the provider's metadata URL with `importUrl()`, reviews the proposal, and saves the settings
   with `ConnectionService::update()` and each certificate with `KeyService::trustCertificate()`; optionally a metadata
   signing anchor with `trustCertificate(..., KeyUse::METADATA_SIGNING)`, then `metadata_url` and `metadata_refresh`.
2. Every 5 minutes the scheduler runs `sso:metadata:refresh` on every server. Each due connection is claimed by one.
3. The claimed refresh fetches the saved URL, verifies the metadata with the anchors, and finds the provider has
   published its next signing certificate beside the current one.
4. Under the lock, nothing changed meanwhile: the new certificate is trusted, nothing is voided, the trust version is
   unchanged, and `[KeyAdded, MetadataRefreshed]` is reported; the next refresh is due a day later.
5. When the provider drops the old certificate, the next refresh distrusts it, voids the flows in flight and raises the
   trust version: `[KeyRetired, MetadataRefreshed]`.

## Failure / Edge Cases

- Two servers refresh the same connection: one claims it and fetches; the other is `skipped`, or `in_progress` for an
  administrator. A claim left by a server that died expires after `claim_seconds`.
- An administrator distrusts a certificate or changes an anchor while a refresh is fetching: the trust version moved,
  the refresh is `conflict` and the administrator's change stands.
- A refresh removes a certificate while a completion through the connection is between validation and its lock: the
  request is voided under the refresh's lock, and the completion is refused `connection_unavailable` under its own.
- A provider whose metadata names another entity id is refused `metadata_entity_not_found` by the reader; an entity id
  changed under the lock is `metadata_invalid`. The entity id never changes through a refresh.
- The metadata server is down for a day: failures back off 300, 600, 1200, ... seconds up to 21600, the last good
  settings serve sign-ins until they expire, and the first success resets the backoff.
- Aggregate metadata larger than `sso.fetcher.max_response_bytes` is refused (`fetch_failed` when fetched); the
  application raises the cap, or points the connection at a per-entity URL.
- A database error propagates (SSO-11.4) and stops a scheduled run; the command reports the exception's class alone.

## Implementation Anchors

- `src/Protocols/Saml2/Library/MetadataReader.php`, `src/Protocols/Saml2/Messages/IdpMetadata.php`.
- `src/Metadata/MetadataImporter.php`, `ProposedSettings.php`, `ImportResult.php`.
- `src/Metadata/MetadataRefresher.php`, `MetadataApplier.php`, `RefreshResult.php`, `Enums/RefreshOutcome.php`,
  `MetadataSettings.php`, `MetadataExpiry.php`, `MetadataCheck.php`.
- `src/Keys/KeyService.php` (`replaceTrustedCertificatesLocked()`), `src/Connections/InFlightVoider.php`.
- `src/Administration/MetadataEvents.php`, `src/Events/MetadataRefreshed.php`, `MetadataRefreshFailed.php`.
- `src/Console/RefreshMetadataCommand.php`.

## Authoritative Tests

- `tests/Feature/Protocols/Saml2/Library/MetadataReaderTest.php`.
- `tests/Feature/Metadata/MetadataImporterTest.php`, `MetadataRefresherTest.php`, `MetadataApplierTest.php`,
  `MetadataEventSequenceTest.php`, `MetadataExpiryTest.php`, `MetadataSettingsTest.php`.
- `tests/Feature/Keys/KeyServiceTest.php` (the replacement), `tests/Feature/Console/RefreshMetadataCommandTest.php`.
- `tests/Integration/Metadata/ConcurrentMetadataRefreshTest.php` (MySQL and PostgreSQL),
  `tests/Integration/Metadata/MetadataEventsAfterCommitTest.php`.
- `tests/Performance/MetadataRefreshQueryBudgetTest.php`.

## Change Triggers

- A change to what the reader accepts: the root, how the entity is chosen, where a signature may be, which signatures
  must verify, the expiry, the bindings or the certificates.
- A change to which connections are due, the claim and its conditions, or the snapshot the compare-and-set compares.
- A change to what a refresh may write, to when it voids and raises the trust version, or to its events.
- A change to the backoff, the refresh interval, the stale limit or the command's output.
