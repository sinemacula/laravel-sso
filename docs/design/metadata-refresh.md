# Metadata Refresh

## Purpose

This note records how a SAML connection is filled in from its identity provider's metadata and kept up to date from
it (SSO-2.8, SSO-6.11, SSO-10.3, SSO-11.12): the metadata validation profile, the import that proposes settings, the
scheduled and on-demand refresh that applies certificates and endpoints, the claim and the compare-and-set that keep
racing servers and administrators from overwriting each other, the trust version, the backoff, and the expiry of what
a refresh applied. The refresh machinery is shared by every protocol through `Metadata\MetadataSource`: an OIDC
connection's discovery document and JWKS refresh through the same claim, compare-and-set, backoff, queue, command,
stale limit and events (`oidc-driver.md`, `oidc-discovery.md`). The SAML adapter it reads metadata through is in
`saml-adapter.md`; the keys and anchors in `keys.md`.

## Invariants

- Metadata is read only by `Protocols\Saml2\Library\MetadataReader`, inside the adapter's namespace, the only place
  the SAML library is called (`saml-adapter.md`). It answers a `Protocols\Saml2\Messages\IdpMetadata`, read
  or refused with a `FailureReason` and the rule's name; the values it holds are in a `\SensitiveParameterValue`,
  redacted from dumps and JSON, and it refuses to be serialised.
- The document is capped at `sso.metadata.max_bytes` (`Metadata\MetadataSettings::maxBytes()`: 64 KiB to a hard
  ceiling of 256 MiB, default 1 MiB, checked at boot while SAML is on), whether it was given as XML or fetched, in place
  of the fetcher's `max_response_bytes`, which every other request keeps. A fetch carries the cap as its own
  (`FetchRequest::metadata($url, $maxBytes)`), and the fetcher stops reading once the response passes it
  (`fetch_failed`); a document over it is never parsed (`metadata_invalid`, `too_large`). The document is parsed by
  the hardened parser: no document type, no entity, no network, no `ID` repeated anywhere in it. Anything else is
  `metadata_invalid`. libxml's default limits bound one text node, name or attribute, never the document, so an
  aggregate of tens of MiB parses without `LIBXML_PARSEHUGE`, which stays off.
- Only the chosen entity is held to the SAML 2.0 metadata schema (`HardenedParser::validateElement()`, the entity copied
  into a document of its own with every namespace in scope where it stood; `metadata_invalid`, `schema`). No other
  member of an aggregate is validated, and none, the chosen entity included, is modelled by the library's
  `EntityDescriptor`, whose stricter rules (a URL with a scheme, a logo by `http`, `https` or `data`, an ASCII email
  address) judge values the reader never reads. A federation member with a value the schema or the library refuses
  never refuses the aggregate for every other connection pinned to it.
- The root is an `EntityDescriptor` or an `EntitiesDescriptor`. The entity is chosen by the pinned entity id alone,
  compared exactly: exactly one `EntityDescriptor` anywhere in the document carries it (none is
  `metadata_entity_not_found`, two `metadata_invalid`, wherever the second hides), and it is the root or a child of an
  `EntitiesDescriptor` that is itself the root or such a child, checked by walking its ancestors. An entity hidden in a
  signature's `Object`, an `Extensions` or anywhere else is refused. Within the entity, the only signature allowed is
  its own.
- With an anchor set (the connection's `metadata_signing` certificates, `Keys\KeyRing::trustedCertificates()`), the
  entity must be covered by a signature, its own or an enclosing `EntitiesDescriptor`'s, and every signature on that
  path must verify with an anchor through `PinnedVerifier`, each signed element copied into a document of its own first
  (`saml-library.md`, condition 3) and verified as a `Protocols\Saml2\Library\SignedDescriptor`, which models the
  signature and the `ID` alone, with the same `SignedInfo` policy as a response. Unsigned metadata, metadata signed
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
  fetcher as a `metadata` request held to the metadata cap (SSO-2.9). It fetches while it is called, so a large
  aggregate is imported from the console or a queued job, never a web request. A proposal that would not be valid
  settings (a single sign-on URL that is not `https`, an entity id that is neither a URL nor a URN) is
  `metadata_invalid`.
- The schedule refreshes a connection only while `sso.features.metadata_refresh` (on by default) is on, its protocol is
  available (`ProtocolManager::isAvailable()`, so a protocol switched off fetches and writes nothing) and its protocol's
  `Metadata\MetadataSource` says it does (`refreshes()`), a protocol with no source never refreshing. For a SAML
  connection (`Metadata\SamlRefreshRule`) that is a `metadata_url` that is a valid `https` URL, and either a
  `metadata_refresh` of `true`, or one left unset on a connection with a metadata signing anchor; `false` is always off.
  HTTPS proves only who served the file, so a URL alone is never trust in what it serves: an anchor is, and an explicit
  `true` delegates that trust to the URL and its TLS. Adding the first anchor turns the default on and removing the last
  turns it off, with no other change. The URL the administrator saved is the only one ever fetched. The OIDC source is
  recorded in `oidc-discovery.md`; there the setting defaults to on. A connection past its stale limit is still due, so
  the schedule recovers it. The due connections are those of the protocols with a source, read on the write connection,
  whose `metadata_refresh_at` is unset or not after now and whose `metadata_claimed_until` is unset or not after now, in
  chunks of 100 by keyset on the id, that refresh; each source judges a chunk at once (`MetadataSource::refreshing()`),
  so the SAML source reads the anchors of a chunk in one statement, since a connection that never refreshes stays due
  and is read on every run. `sso:metadata:refresh` lists their ids (`dueConnectionIds()`) and queues one
  `Metadata\RefreshConnectionMetadata` job per connection, carrying the id alone, on `sso.metadata.queue.connection` and
  `.name`, allowed `.timeout_seconds` (30 to 3600, default 60, never more than `claim_seconds`, and less than the queue
  connection's `retry_after` where it sets one, checked at boot, so a refresh still running is never reserved by a
  second worker and recorded as failed) and `.tries` (default 1, failing on a timeout rather than being released past
  its claim); the job calls `refreshQueued()`, which reads the connection again and is `skipped` when it is gone, no
  longer refreshes or is no longer due. `--sync` refreshes them in the command instead (`refreshDue()`). The job and the
  command each pass `new ClientContext(null, null)`, built where the work starts, so their events carry no IP address or
  user agent; `refreshNow()` takes the administrator's client after their caller. `refreshNow()` refreshes the tenant's
  connection whatever its backoff, its `metadata_refresh` setting or `sso.features.metadata_refresh`, and whether it has
  expired or not, so it recovers a connection the schedule does not: it asks only `MetadataSource::isRefreshable()`,
  that what it fetches is a URL the package may fetch, and that its protocol is available (`connection_not_found` for
  another tenant's, `feature_disabled` for a protocol switched off or nothing to fetch, with nothing fetched), for the
  `Identities\Caller` it requires. Where the schedule would not refresh the connection (its setting or the feature off,
  or a SAML connection that has not opted in) it first asks `sso.connection.trust` freshness for that caller, and
  `stale` is `freshness_required`. It then counts the attempt against `AttemptSubject::metadata()` (the import's limit,
  `sso.rate_limits.metadata`): past it, `rate_limited` with `retryAfter`, before anything is claimed or fetched. Every
  entry refuses to run inside a transaction on the storage connection (`StorageConnection::assertNoTransaction()`).
- The machinery is protocol-agnostic. `Metadata\MetadataRefresher` lists the due connections of every protocol that
  has a source (`Metadata\MetadataSources`: `SamlMetadataSource` for `saml2`, `OidcMetadataSource` for `oidc`; a
  protocol an application registered has none and never refreshes), asks the connection's source whether it refreshes,
  to snapshot and claim it (`RefreshClaims`, which takes the snapshot the source read), to fetch and validate
  (`FetchedMetadata`, read with the moment it validated, or refused with a reason and the fetch's status) and to write
  (`write()`), and logs a refresh that did not apply. `Metadata\RefreshWriter` is every source's write: the
  transaction that locks the connection first, the compare and set (the claim's token, the metadata and trust
  versions, and the source's snapshot read again under the lock), `conflict` reported as the winner left it, a
  failure's backoff and claim release, a success's bookkeeping in the same save as the source's own attributes, and
  `MetadataRefreshed`. `MetadataApplier` is the SAML source's write through it.
- Each refresh reads the connection, then its anchors and its identity provider signing certificates: that is the
  snapshot (metadata version, trust version, the fingerprints of both sets, `Metadata\RefreshClaim`, taken by
  `Metadata\RefreshClaims`). It then claims the connection with one conditional update outside any transaction:
  `metadata_claimed_until = now + claim_seconds` and `metadata_claim_token` a fresh random 128-bit token where the id
  matches, no claim holds and the metadata version is the one read. No row updated is `skipped` (scheduled or queued) or
  `in_progress` (`metadata_refresh_in_progress`, an administrator's), and nothing else happens: an administrator's
  refresh skips the backoff, never a claim.
- Outside any transaction, the claimed refresh fetches the saved URL held to the metadata cap and reads it with the
  pinned `idp_entity_id`, the anchors of the snapshot and the current binding, and notes the moment the reader
  validated it. Only then does it write, in one transaction on the storage connection (`Metadata\MetadataApplier`),
  whose first statement locks the connection's row; the lock order is the connection alone. Every read that decides
  the write is a locking read: the connection, the certificates' and anchors' fingerprints (one statement), and the
  trusted certificates the replacement reads.
- Compare and set, for a success and a failure alike: the locked connection must still hold the claim's token, have the
  snapshot's metadata version and trust version, and the certificates and anchors read under the lock must be exactly
  the snapshot's. Otherwise the refresh is `conflict` (`metadata_conflict`) and writes nothing, not even its claim;
  `MetadataRefreshFailed` reports it with the failures and next attempt as the winner left them. A refresh whose claim
  expired while it fetched and was taken over writes nothing, so two refreshes never both write. Every trust change (a
  certificate removed, an anchor added or removed, the entity id, the endpoints, the metadata URL or switch, a disable)
  raises the trust version under the same lock; a certificate added by an administrator raises none, by design, so the
  certificate set itself is compared, and a refresh based on the configuration before an addition never removes it.
- Under the lock, metadata of an entity other than the locked `idp_entity_id`, or whose endpoint would not be a valid
  setting, is refused `metadata_invalid`, and metadata that has expired by the clock read at commit is refused
  `metadata_expired`: its expiry is the earlier of its `validUntil` and the moment it was validated plus the stale
  limit (`MetadataExpiry::hasExpired()`). Either records a failure.
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
- A successful refresh raises `metadata_version`, sets `metadata_fetched_at` to the moment the fetched document was
  validated (carried from the read into the commit, never the clock at commit), `metadata_valid_until` to the metadata's
  `validUntil`, `metadata_refresh_at` to now plus `refresh_interval_seconds` (never after the `validUntil`), resets
  `metadata_refresh_failures` and releases the claim and its token; `MetadataRefreshed` names the settings changed
  (`sso_url`, `sso_binding`, in that order, then `idp_signing_certificates`), none when nothing did, with the metadata
  version and whether the trust changed.
- A failed refresh (a fetch refused or failed, a response not `2xx`, metadata refused, or a refusal under the lock)
  writes, under the lock and the same compare and set: `metadata_refresh_failures` plus one, `metadata_refresh_at` at
  now plus `MetadataSettings::backoffSeconds()` for that many (5 minutes, doubling, at most 6 hours by default), the
  claim and its token released; the last good settings are kept. `MetadataRefreshFailed` carries the reason,
  the failures and the next attempt; the refresher logs the reason and the fetch's status alone, through the sanitising
  logger, never the URL, the response or the metadata.
- A SAML connection holds a stale deadline only while it follows its metadata URL: a valid `metadata_url` and either a
  `metadata_refresh` of `true` or a metadata signing anchor (`SamlRefreshRule::holdsDeadline()`). `false` on an anchored
  connection keeps the deadline of what a validated fetch applied, as the expiry invariant below says. Any other
  connection, not opted in, behaves like one whose certificates were entered by hand: nothing changes by itself and
  nothing expires, whatever was stamped earlier, so removing the last anchor or the URL, or opting out with no anchor,
  never leaves a connection expiring with nothing to recover it. The trade-off is plain: not opted in, an administrator
  installs a new certificate before the provider switches to it; opted in, trust is delegated to the URL and its TLS,
  which suits a provider whose metadata has no independent anchor. `Connections\ImportSaver::save()` judges the
  connection as its change leaves it, and on one that holds no deadline stamps nothing and clears a stamp left from
  before; an administrator's `refreshNow()` of one still writes what it fetched, and the deadline rule leaves it none.
  Whatever brings a connection to hold a deadline (an update of `metadata_url` or `metadata_refresh`,
  `SamlRefreshRule::resetForSettings()`, or its first anchor, `resetForAnchor()`) clears `metadata_fetched_at`,
  `metadata_valid_until` and `metadata_refresh_at` under the same lock, so a stamp from while it held none, however old,
  never expires it the moment it opts in, and its first refresh is due at once. A change that stays within, or leaves,
  clears nothing. OIDC is not affected by any of this.
- Setting `metadata_refresh` is a trust setting (`Saml2Setting::freshness()`): every change of it, `true` above all,
  goes through `ConnectionService`'s freshness check, raises the trust version and voids what is in flight.
- Expiry does not depend on scheduling. Every validated fetched resource expires (`Metadata\MetadataExpiry`, which the
  driver checks before every start, completion and re-initiation, and the completion and the re-initiation check again
  on the locked connection, failing with `metadata_expired`), counted from its own validated fetch: the document at the
  earlier of `metadata_valid_until` (the earliest `validUntil` of the entity and every aggregate around it) and
  `metadata_fetched_at` plus `sso.metadata.stale_limit_seconds` (30 days by default; `0`, set explicitly, for no limit),
  the same rule the refresh applied at commit; an OIDC connection's JWKS from `jwks_fetched_at` plus the same limit
  (`oidc-discovery.md`). Turning the schedule off never means unlimited trust, but for a SAML connection that holds no
  deadline, above. An import is a validated fetch: saving what one proposes through `Connections\ImportSaver::save()`
  stamps `metadata_fetched_at` and `metadata_valid_until` from the proposal (`ProposedSettings::fetch()`), so its stale
  limit and `validUntil` apply from that fetch whether or not a refresh ever runs. A connection with nothing fetched
  yet, its settings and keys saved by hand, metadata given as XML among them, has no deadline: nothing it holds came
  from a fetch that could go stale, and the first fetch of each resource starts its clock. The expired last good
  settings stay stored, for diagnosis, until a scheduled or administrator's refresh succeeds. A callback never recovers
  a connection: the driver refuses it before anything is fetched.
- Events (`Administration\MetadataEvents`) are built through the one context projection, with the identity of the
  administrator's caller who asked as the acting identity, or none for a scheduled run, and dispatched after the
  transaction commits, never on a rollback. None holds a certificate, a URL or any value of the metadata.
- A scheduled refresh asks no freshness: it is a system job an administrator set up, with freshness, by saving the
  `metadata_url` or issuer, the anchor or `metadata_refresh`. An administrator's refresh asks none where the schedule
  would refresh the connection too, since it writes no more than the schedule would; it is rate limited and names the
  administrator instead. Where the schedule would not, the same refresh would replace what an administrator told the
  schedule to leave alone, so it asks `sso.connection.trust` (SSO-2.12).
- Large federation metadata is supported once the cap allows it: the aggregate's signature is verified whole with the
  anchor and exactly one entity with the pinned id chosen. The whole document is held in memory, parsed and its
  signature checked in one piece (the library rebuilds the signed aggregate twice to verify it), so memory runs to
  several times the file's size and processing to seconds for tens of MiB. The refresh runs on the queue the
  deployment sizes for it (the worker's memory limit and timeout, the job's `timeout_seconds`, `claim_seconds` at
  least as long, the queue connection's `retry_after` longer still). The download itself is bounded by the fetcher's
  `timeout_seconds` (`SSO_FETCHER_TIMEOUT_SECONDS`, 10 by default, at most 60), which every outbound request shares:
  raising it raises the deadline of every token, UserInfo, discovery and JWKS request too. A file of 64 MiB needs a
  sustained 54 Mbit/s to arrive in the default 10 seconds, and 9 Mbit/s in 60. A per-entity URL (MDQ) is preferred
  wherever the federation offers one, and is the only way when the aggregate cannot download within 60 seconds.

## Success Path

1. An administrator imports the provider's metadata URL with `importUrl()`, reviews the proposal, and saves the settings
   with `ImportSaver::save()` and each certificate with `KeyService::trustCertificate()`; then a metadata signing anchor
   with `trustCertificate(..., KeyUse::METADATA_SIGNING)`, or `metadata_refresh` set `true`, then `metadata_url`.
2. Every 5 minutes the scheduler runs `sso:metadata:refresh` on every server, which queues a job per due connection.
   Each due connection is claimed by one job.
3. The claimed refresh fetches the saved URL, verifies the metadata with the anchors, and finds the provider has
   published its next signing certificate beside the current one.
4. Under the lock, nothing changed meanwhile: the new certificate is trusted, nothing is voided, the trust version is
   unchanged, and `[KeyAdded, MetadataRefreshed]` is reported; the next refresh is due a day later.
5. When the provider drops the old certificate, the next refresh distrusts it, voids the flows in flight and raises the
   trust version: `[KeyRetired, MetadataRefreshed]`.

## Failure / Edge Cases

- Two servers refresh the same connection: one claims it and fetches; the other is `skipped`, or `in_progress` for an
  administrator. A claim left by a server that died expires after `claim_seconds`.
- A refresh outlives its claim (a slow fetch of a large aggregate), and another server claims the connection: the
  first refresh's token no longer matches, so it writes nothing, success or failure, and the second refresh stands.
- An administrator distrusts a certificate or changes an anchor while a refresh is fetching: the trust version moved,
  the refresh is `conflict` and the administrator's change stands. One who adds a certificate raises no trust version,
  but the certificate set moved: the refresh is `conflict` and never removes it.
- An administrator's refresh now past the metadata limit is `rate_limited`, with nothing claimed or fetched.
- An administrator removes a connection's last anchor, with `metadata_refresh` unset: the schedule stops, a refresh
  already fetching is `conflict`, and the stamps it holds no longer expire it. The anchor added back clears them.
- A connection imported, then left with no anchor and no opt-in, has no clock: 30 days on it still signs in. An
  administrator's refresh now, asked with fresh authentication, replaces its certificates once and starts none.
- A queued job that waited while another server refreshed the connection finds it no longer due and is `skipped`.
- A refresh removes a certificate while a completion through the connection is between validation and its lock: the
  request is voided under the refresh's lock, and the completion is refused `connection_unavailable` under its own.
- A provider whose metadata names another entity id is refused `metadata_entity_not_found` by the reader; an entity id
  changed under the lock is `metadata_invalid`. The entity id never changes through a refresh.
- The metadata server is down for a day: failures back off 300, 600, 1200, ... seconds up to 21600, the last good
  settings serve sign-ins until they expire, and the first success resets the backoff.
- A federation member other than the pinned entity holds a value the schema or the library's model refuses (a relative
  `mdui:Logo`, an `OrganizationURL` with no scheme, an unknown `contactType`): it is never validated or modelled, the
  aggregate's signature verifies over its bytes, and the pinned entity is read.
- Aggregate metadata larger than `sso.metadata.max_bytes` is refused (`fetch_failed` when fetched, the transfer stopped
  at the cap; `metadata_invalid` given as XML); the application raises the cap and sizes its queue, or points the
  connection at a per-entity URL.
- Metadata validated the stale limit or longer before the refresh commits (a refresh stalled for longer than it) is
  refused `metadata_expired` at commit, though its `validUntil` is far off.
- A database error propagates (SSO-11.4) and stops a scheduled run; the command reports the exception's class alone.

## Implementation Anchors

- `src/Protocols/Saml2/Library/MetadataReader.php`, `SignedDescriptor.php`, `HardenedParser.php`,
  `src/Protocols/Saml2/Messages/IdpMetadata.php`.
- `src/Metadata/MetadataImporter.php`, `ProposedSettings.php`, `ImportResult.php`, `ValidatedFetch.php`,
  `src/Connections/ImportSaver.php`.
- `src/Metadata/MetadataRefresher.php`, `MetadataSource.php`, `MetadataSources.php`, `SamlMetadataSource.php`,
  `SamlRefreshRule.php`, `OidcMetadataSource.php`, `FetchedMetadata.php`, `RefreshWriter.php`, `MetadataApplier.php`,
  `RefreshClaims.php`, `RefreshClaim.php`, `RefreshConnectionMetadata.php`, `RefreshResult.php`,
  `Enums/RefreshOutcome.php`, `MetadataSettings.php`, `MetadataExpiry.php`, `MetadataCheck.php`.
- `src/Fetching/FetchRequest.php` (the per-call cap), `src/Fetching/GuzzleFetcher.php`.
- `src/Keys/KeyService.php` (`replaceTrustedCertificatesLocked()`), `src/Connections/InFlightVoider.php`.
- `src/Administration/MetadataEvents.php`, `src/Events/MetadataRefreshed.php`, `MetadataRefreshFailed.php`.
- `src/Console/RefreshMetadataCommand.php`.

## Authoritative Tests

- `tests/Feature/Protocols/Saml2/Library/MetadataReaderTest.php` (the cap at, under and over it; a signed aggregate of
  several MiB; an unrelated member the schema or the library refuses; the chosen entity validated with its
  aggregate's namespaces).
- `tests/Feature/Connections/ImportSaverTest.php` (a fetched import counts from its fetch where the connection holds a
  deadline, for each anchor and switch; XML does not).
- `tests/Feature/Metadata/SamlRefreshRuleTest.php` (the schedule for each anchor and switch; an anchor added and removed
  later; opting in needing freshness and raising the trust version; an administrator's refresh that starts no clock).
- `tests/Feature/Fetching/GuzzleFetcherTest.php` and `tests/Unit/Fetching/FetchRequestTest.php` (a request's own cap).
- `tests/Feature/Metadata/MetadataImporterTest.php`, `MetadataRefresherTest.php`, `MetadataApplierTest.php`,
  `MetadataEventSequenceTest.php`, `MetadataExpiryTest.php`, `MetadataSettingsTest.php`, `MetadataSourcesTest.php`,
  `RefreshWriterTest.php` (the compare and set, each mismatch alone; the backoff; the bookkeeping),
  `SamlMetadataSourceTest.php`.
- `tests/Feature/Keys/KeyServiceTest.php` (the replacement), `tests/Feature/Console/RefreshMetadataCommandTest.php`.
- `tests/Integration/Metadata/ConcurrentMetadataRefreshTest.php` (MySQL and PostgreSQL: an addition, a distrust and an
  anchor while a refresh fetched; a claim taken over),
  `tests/Integration/Metadata/MetadataEventsAfterCommitTest.php`.
- `tests/Performance/MetadataRefreshQueryBudgetTest.php`.

## Change Triggers

- A change to what the reader accepts: the root, how the entity is chosen, where a signature may be, which signatures
  must verify, the expiry, the bindings or the certificates.
- A change to which connections are due, the claim and its conditions, or the snapshot the compare-and-set compares.
- A change to what brings a SAML connection to follow its metadata URL, or what it holds a stale deadline for.
- A change to what a refresh may write, to when it voids and raises the trust version, or to its events.
- A change to the backoff, the refresh interval, the stale limit, the size cap, the queue or the command's output.
- libxml or the SAML library limiting a document's size, which would need `LIBXML_PARSEHUGE` behind the cap.
