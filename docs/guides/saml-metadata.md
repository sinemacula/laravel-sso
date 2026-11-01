# SAML Metadata

An identity provider describes itself in SAML 2.0 metadata: its entity id, where to send people to sign in, and the
certificates it signs with. The package can fill a SAML connection in from that metadata, given as XML or fetched from a
URL, and, when you switch it on, keep the connection's certificates and sign-in endpoint up to date from it on a
schedule. See [Managing connections](managing-connections.md) for the settings themselves and [Keys](keys.md) for
trusted certificates.

## Importing metadata

`MetadataImporter` reads the metadata and answers the settings it proposes. Nothing is written or trusted: you show the
proposal to the administrator, and save what they accept.

```php
use SineMacula\Laravel\Sso\Metadata\MetadataImporter;

$result = app(MetadataImporter::class)->importUrl(
    tenantId: $tenant->id,
    connectionId: $connection->id, // or null before the connection exists
    url: 'https://idp.example.com/metadata.xml',
    entityId: 'https://idp.example.com/saml',
);

if ($result->isRateLimited()) {
    return back()->withErrors(['metadata' => "Try again in {$result->retryAfter} seconds."]);
}

if ($result->isRefused()) {
    return back()->withErrors(['metadata' => $result->reason->value]);
}

$proposed = $result->proposed;

$proposed->settings();               // ['idp_entity_id' => ..., 'sso_url' => ..., 'sso_binding' => 'http_redirect']
$proposed->signingCertificates();    // [['certificate' => '-----BEGIN CERTIFICATE-----...', 'fingerprint' => '...']]
$proposed->encryptionCertificates(); // the same shape
$proposed->nameIdFormats();          // ['urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', ...]
$proposed->validUntil();             // a CarbonImmutable, or null
```

`importXml()` takes the document instead of a URL, for metadata an administrator uploads. The entity id is required:
from aggregate metadata (a federation's `EntitiesDescriptor`) the entity is chosen by that id alone, and metadata that
names it twice is refused.

Once the administrator has compared the certificate fingerprints with the ones the provider gave them, save the
proposal:

```php
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Keys\KeyService;

app(ConnectionService::class)->update($tenant->id, $connection->id, ['settings' => $proposed->settings()], $actor);

foreach ($proposed->signingCertificates() as $certificate) {
    app(KeyService::class)->trustCertificate($tenant->id, $connection->id, $certificate['certificate'], $actor);
}
```

Each of those asks the freshness contract, as any trust change does. The proposal never sets the NameID format: choose
`name_id_format` from `nameIdFormats()` yourself.

| Reason                       | When                                                                                                                                                                             |
|------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `protocol_unavailable`       | The `saml2` feature is off: nothing is looked up, read or fetched                                                                                                                |
| `connection_not_found`       | The connection named is unknown, another tenant's, or not a SAML connection                                                                                                      |
| `fetch_refused`              | The URL is not `https`, or resolves to an address the fetcher refuses                                                                                                            |
| `fetch_failed`               | The request failed, timed out, was too large, or did not answer `2xx`                                                                                                            |
| `metadata_invalid`           | Unparseable, not valid metadata, too large, the entity in the wrong place or named twice, no usable sign-on service or signing certificate, or settings a connection cannot hold |
| `metadata_signature_invalid` | The connection has a metadata signing anchor, and the metadata is unsigned or signed by another key                                                                              |
| `metadata_entity_not_found`  | No entity with the id given                                                                                                                                                      |
| `metadata_expired`           | The metadata's `validUntil` has passed                                                                                                                                           |

`detail` names the rule that refused the metadata (`schema`, `duplicate_entity`, `entity_location`, `signature`,
`sso_service`, ...), for your logs; it never quotes the metadata. Naming a connection counts each URL import against
`sso.rate_limits.metadata` (10 an hour per connection by default).

Only the HTTP-Redirect and HTTP-POST bindings are used, the connection's current one preferred; only RSA certificates of
at least 2048 bits are proposed, since those are what the package's SAML library verifies. An import reports no event.

## A metadata signing anchor

A provider, or a federation, may sign its metadata. Trust the signer's certificate as a metadata signing anchor, and
every import that names the connection, and every refresh, must then be signed by it:

```php
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;

app(KeyService::class)->trustCertificate($tenant->id, $connection->id, $anchor, $actor, KeyUse::METADATA_SIGNING);
```

The entity must be covered by a signature that verifies with an anchor (its own, or an enclosing aggregate's), and every
signature on the way to it must verify. Changing the anchors is a trust change: it asks freshness and voids the flows in
flight, so a refresh that began before it is refused.

## Refreshing on a schedule

Refreshing is off unless you switch it on, for the application and then per connection:

```dotenv
SSO_METADATA_REFRESH=true
```

```php
app(ConnectionService::class)->update($tenant->id, $connection->id, ['settings' => [
    'metadata_url'     => 'https://idp.example.com/metadata.xml',
    'metadata_refresh' => true,
]], $actor);
```

A refresh fetches only that saved `https` URL, reads the entity the connection already names (`idp_entity_id`, never
changed by a refresh), checks the signature when the connection has an anchor, and then changes only:

- the trusted signing certificates, replaced exactly: a certificate the metadata no longer lists is distrusted, and a
  new one trusted;
- the single sign-on URL and binding.

It never touches the subject settings, the attribute mapping or enforcement. A refresh that only adds a certificate (a
provider publishing its next key) leaves the flows in flight alone; one that removes or replaces a certificate, or moves
the sign-on endpoint, voids them, as the same change by hand would.

Run the command from the scheduler, every 5 minutes or more often:

```php
// bootstrap/app.php
use Illuminate\Console\Scheduling\Schedule;

->withSchedule(function (Schedule $schedule): void {
    $schedule->command('sso:metadata:refresh')->everyFiveMinutes();
})
```

It refreshes only what is due: a day after a success (`sso.metadata.refresh_interval_seconds`), never after the
metadata's own `validUntil`, and after a failure 5 minutes, doubling with each failure in a row up to 6 hours
(`backoff_initial_seconds`, `backoff_max_seconds`). The schedule must run at least as often as the first backoff, or a
retry waits for the next run. It is safe on several servers at once: each connection is claimed by one server
(`claim_seconds`, 5 minutes by default) and the others skip it, so `onOneServer()` is not needed.

The command prints the count of each outcome and nothing of any connection:

```text
Metadata refreshed: refreshed 3, failed 1, conflict 0, in_progress 0, skipped 1, refused 0
```

It exits 0 whatever the outcomes, which the events report; and 1 only when the run stopped on an exception, which it
names by class alone.

To refresh a connection at once, for an administrator, skipping its backoff:

```php
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;

$result = app(MetadataRefresher::class)->refreshNow($tenant->id, $connection->id, $actor);

$result->outcome;         // RefreshOutcome::REFRESHED, FAILED, CONFLICT, IN_PROGRESS or REFUSED
$result->changedSettings; // ['sso_url', 'idp_signing_certificates'], say
```

`in_progress` means another server is refreshing it now; a refresh never runs twice at once.

| Outcome       | When                                                                                     |
|---------------|------------------------------------------------------------------------------------------|
| `refreshed`   | The metadata was applied (changing something or nothing)                                 |
| `failed`      | The fetch or the metadata was refused; the last good settings are kept, and it backs off |
| `conflict`    | The connection's trust or anchors changed while it fetched; nothing was written          |
| `in_progress` | Another server holds the connection's claim                                              |
| `skipped`     | A scheduled run found it claimed or refreshed by another server                          |
| `refused`     | `refreshNow()` named no such connection, or one that does not refresh                    |

## When refreshed settings expire

Settings a refresh applied stop being used, and sign-ins through the connection fail with `metadata_expired` until a
refresh succeeds, at the earlier of:

- the metadata's `validUntil`, the earliest of the entity and every aggregate around it;
- 30 days after the last successful refresh (`sso.metadata.stale_limit_seconds`, a day to a year).

Undated metadata is bounded by the second alone. Setting `stale_limit_seconds` to `0` removes the limit; you must set it
explicitly, and then only a `validUntil` ever expires the settings. A connection no refresh has written (its settings
entered by hand or imported once) never expires.

## Aggregates and the size cap

Every document, imported or fetched, is capped at `sso.fetcher.max_response_bytes` (1 MiB by default). A federation's
aggregate metadata is often much larger: point the connection at the federation's per-entity URL (its MDQ service) when
it has one, or raise the cap for the application.

## Events

| Event                   | Carries                                                                                      |
|-------------------------|----------------------------------------------------------------------------------------------|
| `MetadataRefreshed`     | `changedSettings` (names only, none when nothing changed), `metadataVersion`, `trustChanged` |
| `MetadataRefreshFailed` | `reason`, `failures` in a row, `nextAttemptAt`                                               |

A refresh that changes certificates also reports `KeyRetired` and `KeyAdded`, and one that moves the endpoint
`ConnectionUpdated`, before `MetadataRefreshed`. Each event's context names the connection and, for `refreshNow()`, the
acting identity you passed; a scheduled refresh has none. No event carries a certificate, a URL or the metadata. Each is
dispatched after the refresh's transaction commits; see [Events](events.md).
