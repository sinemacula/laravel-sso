# SAML Metadata

An identity provider describes itself in SAML 2.0 metadata: its entity id, where to send people to sign in, and the
certificates it signs with. The package can fill a SAML connection in from that metadata, given as XML or fetched from a
URL, and keep the connection's certificates and sign-in endpoint up to date from it on a schedule, where you have given
it a reason to trust what the URL serves: a metadata signing anchor, or an explicit opt-in (see
[Refreshing on a schedule](#refreshing-on-a-schedule)). See [Managing connections](managing-connections.md) for the
settings themselves and [Keys](keys.md) for trusted certificates.

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

`importUrl()` fetches while you call it. A provider's own metadata is a few KiB; a federation's aggregate may be tens of
MiB and take seconds to fetch and check, so import such a URL from the console or a queued job, never in a web request
(see [Large federation metadata](#large-federation-metadata)).

Once the administrator has compared the certificate fingerprints with the ones the provider gave them, save the
proposal:

```php
use SineMacula\Laravel\Sso\Connections\ImportSaver;
use SineMacula\Laravel\Sso\Keys\KeyService;

app(ImportSaver::class)->save($tenant->id, $connection->id, ['settings' => $proposed->settings()], $proposed->fetch(), $actor);

foreach ($proposed->signingCertificates() as $certificate) {
    app(KeyService::class)->trustCertificate($tenant->id, $connection->id, $certificate['certificate'], $actor);
}
```

Each of those asks the freshness contract, as any trust change does. The proposal never sets the NameID format: choose
`name_id_format` from `nameIdFormats()` yourself.

`save()` makes the update `ConnectionService::update()` would and, on a connection that [follows its metadata
URL](#refreshing-on-a-schedule) as the save leaves it, stamps the fetch `fetch()` carries, so [what you saved
expires](#when-refreshed-settings-expire) from that fetch, even with `metadata_refresh` set `false` on an anchored
connection. A connection that has not opted in starts no clock: nothing would refresh it, so what you reviewed counts as
certificates entered by hand, and does not expire. Metadata you gave as XML came from no fetch: `fetch()` is `null`, and
you save it with `ConnectionService::update()`, as by hand. On a connection with a deadline, saving a new import of the
same settings renews it, on the record, as `ConnectionUpdated` naming `metadata_fetched_at`, and voids nothing.

| Reason                       | When                                                                                                                                                                             |
|------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `protocol_unavailable`       | The `saml2` feature is off: nothing is looked up, read or fetched                                                                                                                |
| `connection_not_found`       | The connection named is unknown, another tenant's, or not a SAML connection                                                                                                      |
| `fetch_refused`              | The URL is not `https`, or resolves to an address the fetcher refuses                                                                                                            |
| `fetch_failed`               | The request failed, timed out, was larger than `sso.metadata.max_bytes`, or did not answer `2xx`                                                                                 |
| `metadata_invalid`           | Unparseable, not valid metadata, too large, the entity in the wrong place or named twice, no usable sign-on service or signing certificate, or settings a connection cannot hold |
| `metadata_signature_invalid` | The connection has a metadata signing anchor, and the metadata is unsigned or signed by another key                                                                              |
| `metadata_entity_not_found`  | No entity with the id given                                                                                                                                                      |
| `metadata_expired`           | The metadata's `validUntil` has passed                                                                                                                                           |

`detail` names the rule that refused the metadata (`schema`, `duplicate_entity`, `entity_location`, `signature`,
`sso_service`, ...), for your logs; it never quotes the metadata. Naming a connection counts each URL import against
`sso.rate_limits.metadata` (10 an hour per connection by default).

Only the HTTP-Redirect and HTTP-POST bindings are used, the connection's current one preferred; only RSA certificates of
at least 2048 bits are proposed, since SAML is RSA only until the package's PHP floor moves to 8.5 (see
[Setting up a SAML connection](saml-connections.md#saml-is-rsa-only)). An import reports no event.

## A metadata signing anchor

A provider, or a federation, may sign its metadata. Trust the signer's certificate as a metadata signing anchor, and
every import that names the connection, and every refresh, must then be signed by it:

```php
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;

app(KeyService::class)->trustCertificate($tenant->id, $connection->id, $anchor, $actor, KeyUse::METADATA_SIGNING);
```

The entity must be covered by a signature that verifies with an anchor (its own, or an enclosing aggregate's), and every
signature on the way to it must verify. Changing the anchors is a trust change: it asks freshness and voids the flows in
flight, so a refresh that began before it is refused. An anchor is also what lets a connection with a `metadata_url`
[refresh by default](#refreshing-on-a-schedule): adding the first turns that on, and removing the last turns it off.

## Refreshing on a schedule

A refresh replaces a connection's trusted signing certificates with what its metadata lists, and HTTPS proves only who
served the file. So a `metadata_url` alone refreshes nothing. A connection with a `metadata_url` refreshes on the
schedule when it has a [metadata signing anchor](#a-metadata-signing-anchor), or when an administrator has set
`metadata_refresh` to `true`:

| Metadata signing anchor | `metadata_refresh` | On the schedule | Stale deadline                        |
|-------------------------|--------------------|-----------------|---------------------------------------|
| Yes                     | unset              | Refreshes       | From its last validated fetch         |
| Yes                     | `true`             | Refreshes       | From its last validated fetch         |
| Yes                     | `false`            | Left alone      | From its last validated fetch, if any |
| No                      | unset              | Left alone      | None                                  |
| No                      | `true`             | Refreshes       | From its last validated fetch         |
| No                      | `false`            | Left alone      | None                                  |

A connection with no `metadata_url` never refreshes and has no deadline. Adding an anchor to a connection with a URL
turns the default on, and removing the last turns it off, with no other change.

```php
app(ConnectionService::class)->update($tenant->id, $connection->id, ['settings' => [
    'metadata_url' => 'https://idp.example.com/metadata.xml',
]], $actor);

// With the provider's or the federation's signing certificate as an anchor, that is all it takes.
app(KeyService::class)->trustCertificate($tenant->id, $connection->id, $anchor, $actor, KeyUse::METADATA_SIGNING);
```

**Choose what you are trusting.** The two ways of keeping up with a provider's certificates each have a cost:

- **Not opted in**, with no anchor: nothing changes by itself. The connection behaves as if its certificates were
  entered by hand, has no stale deadline and keeps working, but an administrator must install a new certificate before
  the provider switches to it, or sign-ins fail until they do.
- **Opted in**, `metadata_refresh` set `true` with no anchor: the certificates follow the provider by themselves, but
  whoever controls that URL and its TLS decides which certificates you trust. This suits providers whose metadata has no
  independent anchor, where you accept that delegation. Setting it is a trust change, so it asks
  `sso.connection.trust` freshness, raises the trust version and voids the flows in flight, as every change of
  `metadata_refresh` does.

Where the provider signs its metadata, an anchor gives you the automatic refresh without that delegation: prefer it.
Whatever brings a connection to follow its URL (the switch, the anchor, or the URL itself on an anchored connection)
makes its first refresh due at once and starts no clock from anything stamped before.

Set `metadata_refresh` to `false` to keep an anchored connection off, or `SSO_METADATA_REFRESH=false` to stop the
schedule for the whole application. Neither stops [what a refresh applied expiring](#when-refreshed-settings-expire),
and an administrator's refresh still works. With `sso.features.saml2` off, nothing refreshes and nothing fetches.

A refresh fetches only that saved `https` URL, reads the entity the connection already names (`idp_entity_id`, never
changed by a refresh), checks the signature when the connection has an anchor, and then changes only:

- the trusted signing certificates, replaced exactly: a certificate the metadata no longer lists is distrusted, and a
  new one trusted;
- the single sign-on URL and binding.

It never touches the subject settings, the attribute mapping or enforcement. A refresh that only adds a certificate (a
provider publishing its next key) leaves the flows in flight alone; one that removes or replaces a certificate, or moves
the sign-on endpoint, voids them, as the same change by hand would.

**You must run the command**, or nothing refreshes and the fetched settings of a connection that follows its URL expire
after 30 days: run it from the scheduler, every 5 minutes or more often, with `php artisan schedule:work` or a cron
entry for `schedule:run`. Each job goes to your application's default queue connection (`database` in a stock Laravel
install) unless `SSO_METADATA_QUEUE_CONNECTION` says otherwise, so run `php artisan queue:work` for it, unless that
connection is `sync` or the command runs with `--sync`.

```php
// bootstrap/app.php
use Illuminate\Console\Scheduling\Schedule;

->withSchedule(function (Schedule $schedule): void {
    $schedule->command('sso:metadata:refresh')->everyFiveMinutes();
})
```

The command lists the connections due and queues one `RefreshConnectionMetadata` job for each, carrying the
connection's id alone, so fetching and checking the metadata runs on a queue worker rather than in the scheduler. Choose
where it goes and how long it may run:

```php
// config/sso.php
'metadata' => [
    'queue' => [
        'connection'      => env('SSO_METADATA_QUEUE_CONNECTION'), // null: the default queue connection
        'name'            => env('SSO_METADATA_QUEUE'),            // null: that connection's default queue
        'timeout_seconds' => 60,                                   // 30 to 3600, at most claim_seconds
        'tries'           => 1,                                    // a failure is retried by the backoff instead
    ],
],
```

A job times out as a failure, never released for another attempt past its claim. Its timeout must be shorter than the
`retry_after` of the queue connection it is sent to (90 seconds in Laravel's stock `config/queue.php`), or a refresh
still running is reserved by a second worker and recorded as a failed job; the boot check refuses one that is not. Each
job reads its connection again and refreshes it only while it is still due, so a job that waited in the queue while
another server refreshed the connection does nothing. Pass `--sync` to refresh every due connection in the command
itself, one after the other, with no queue: for an application with no worker, or to run a refresh by hand.

A connection is due a day after a success (`sso.metadata.refresh_interval_seconds`), never after the metadata's own
`validUntil`, and after a failure 5 minutes, doubling with each failure in a row up to 6 hours
(`backoff_initial_seconds`, `backoff_max_seconds`). The schedule must run at least as often as the first backoff, or a
retry waits for the next run. It is safe on several servers at once: each connection is claimed by one refresh
(`claim_seconds`, 5 minutes by default) with a token of its own, and the others skip it, so `onOneServer()` is not
needed. A refresh whose claim ran out while it fetched, and was taken over by another, writes nothing.

The command prints one line and nothing of any connection: how many refreshes it queued, or with `--sync` the count of
each outcome:

```text
Metadata refreshes queued: 4
Metadata refreshed: refreshed 3, failed 1, conflict 0, in_progress 0, rate_limited 0, skipped 1, refused 0
```

It exits 0 whatever the outcomes, which the events report; and 1 only when the run stopped on an exception, which it
names by class alone.

To refresh a connection at once, for an administrator, name the administrator who asked. This skips its backoff, and
works with the schedule off, with the connection's `metadata_refresh` off, on a connection that has not opted in and on
one that has already expired, so it is how you recover one the schedule does not touch, or apply a provider's new
metadata once to one you keep by hand. It needs only a `metadata_url`. A connection that has not opted in gains no stale
deadline from it, and the schedule goes on leaving it alone:

```php
use SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;

$result = app(MetadataRefresher::class)->refreshNow($tenant->id, $connection->id, $actor);

if ($result->outcome === RefreshOutcome::RATE_LIMITED) {
    return back()->withErrors(['metadata' => "Try again in {$result->retryAfter} seconds."]);
}

$result->outcome;         // RefreshOutcome::REFRESHED, FAILED, CONFLICT, IN_PROGRESS, RATE_LIMITED or REFUSED
$result->changedSettings; // ['sso_url', 'idp_signing_certificates'], say
```

The acting identity is required: every refresh an administrator asks for is reported as theirs. Each counts against the
connection's metadata limit (`sso.rate_limits.metadata`, 10 an hour per connection by default, shared with URL imports
naming the connection) before anything is claimed or fetched, so an administrator cannot hammer the provider.
`refreshNow()` runs in the request that calls it, so call it from a queued job when the metadata is large. Where the
schedule would refresh the connection too it asks no freshness, since it writes no more than the schedule would. With
`metadata_refresh` or `SSO_METADATA_REFRESH` off, or on a connection that has not opted in, it asks the freshness
contract as `sso.connection.trust`, since it replaces what the schedule leaves alone. `in_progress` means another server
is refreshing it now; a refresh never runs twice at once.

| Outcome        | When                                                                                                      |
|----------------|-----------------------------------------------------------------------------------------------------------|
| `refreshed`    | The metadata was applied (changing something or nothing)                                                  |
| `failed`       | The fetch or the metadata was refused; the last good settings are kept, and it backs off                  |
| `conflict`     | Its claim was taken over, or the trust, certificates or anchors changed while it fetched; nothing written |
| `in_progress`  | Another server holds the connection's claim                                                               |
| `rate_limited` | `refreshNow()` past the connection's metadata limit, with `retryAfter`; nothing ran                       |
| `skipped`      | A scheduled or queued run found it claimed, refreshed by another server, or no longer due                 |
| `refused`      | `refreshNow()` named no such connection, its protocol is off, it has no URL, or freshness was refused     |

A certificate an administrator trusts while a refresh is fetching is never removed by that refresh, even though a
refresh replaces the certificates exactly: the refresh compares the certificates and anchors it read before it fetched
with the connection's when it writes, and any difference, an addition included, is a `conflict` that leaves the
administrator's change standing. The next refresh starts from it.

## When refreshed settings expire

On a connection that follows its metadata URL (see the [table above](#refreshing-on-a-schedule)), settings a refresh
applied stop being used, and sign-ins through the connection fail with `metadata_expired` until a scheduled or
administrator's refresh succeeds, at the earlier of:

- the metadata's `validUntil`, the earliest of the entity and every aggregate around it;
- 30 days after the last successful refresh validated the document it applied (`sso.metadata.stale_limit_seconds`, a
  day to a year): the moment the fetched document was validated, not the later moment its write committed. A refresh
  checks this again when it commits, so it never writes metadata that has already expired.

This does not depend on the schedule: turning it off, or setting `metadata_refresh` to `false` on an anchored
connection, never means unlimited trust. Undated metadata is bounded by the second alone. Setting `stale_limit_seconds`
to `0` removes the limit; you must set it explicitly, and then only a `validUntil` ever expires the settings. Settings
[saved from a fetched import](#importing-metadata) count from that fetch and its `validUntil`, so the same limits apply
before any refresh has run. A connection nothing has fetched for yet, its settings entered by hand or given as XML, has
no deadline: nothing it holds came from a fetch that could go stale. Its first refresh starts the clock.

A connection that does not follow its URL (no anchor and `metadata_refresh` not `true`, or no `metadata_url` at all) has
no deadline either, whatever was stamped on it earlier: nothing would refresh it, so it keeps working, its certificates
treated as entered by hand. Removing the last anchor, or the URL, or opting out with no anchor, therefore ends a
deadline that was running rather than leaving the connection to expire with nothing to recover it. It starts again from
the next validated fetch once something brings the connection back.

## Large federation metadata

Every metadata document, imported or refreshed, given as XML or fetched, is capped at `sso.metadata.max_bytes`: 1 MiB by
default, configurable up to a hard ceiling of 256 MiB, and checked at boot. It replaces the fetcher's
`max_response_bytes` for metadata alone; every other request to a provider (discovery, JWKS, token, UserInfo) keeps the
fetcher's cap. A fetch stops reading as soon as the response passes the cap (`fetch_failed`), and a document over it is
never parsed (`metadata_invalid`, `too_large`).

A federation's aggregate (an `EntitiesDescriptor` of every member) is supported out of the box once the cap allows it:

- the aggregate's signature is verified whole with the connection's metadata signing anchor, and every signature on the
  way to the entity must verify too;
- only the chosen entity is checked against the metadata schema; no other member is validated, so one a federation
  lists with a value the schema or the SAML library refuses (a relative logo, an organisation URL with no scheme, an
  unknown contact type) never refuses the aggregate;
- exactly one `EntityDescriptor` with the connection's pinned entity id is chosen from it; none is
  `metadata_entity_not_found`, two `metadata_invalid`;
- the earliest `validUntil` of the entity and the aggregate around it is the metadata's expiry.

> **Warning: a raised cap loads the whole file.** The aggregate is downloaded, held in memory, parsed and its signature
> checked in one piece on every import and every refresh. Expect memory of several times the file's size and seconds
> of processing for tens of MiB. Size the queue the refresh is sent to for it: the worker's memory limit (`--memory`)
> and timeout (`--timeout`, above `sso.metadata.queue.timeout_seconds`), the job's `timeout_seconds`,
> `claim_seconds` at least as long, and the queue connection's `retry_after` longer than the job's timeout. The
> download is bounded by the fetcher's `timeout_seconds` (`SSO_FETCHER_TIMEOUT_SECONDS`, 10 by default, at most 60),
> which every outbound request shares, so raising it raises the deadline of token, UserInfo, discovery and JWKS requests
> too: a file of 64 MiB needs a sustained 54 Mbit/s to arrive in 10 seconds, and 9 Mbit/s in 60. Import such a URL
> from the console or a queued job, never a web request. Where the federation publishes a URL per entity (an MDQ
> service), use it instead: it is a few KiB, needs no raised cap, and is still signed by the federation; it is the only
> way when the aggregate cannot download within 60 seconds.

```dotenv
SSO_METADATA_MAX_BYTES=67108864
SSO_FETCHER_TIMEOUT_SECONDS=60
SSO_METADATA_QUEUE_CONNECTION=redis
SSO_METADATA_QUEUE=metadata
SSO_METADATA_QUEUE_TIMEOUT_SECONDS=600
SSO_METADATA_CLAIM_SECONDS=900
REDIS_QUEUE_RETRY_AFTER=660
```

```bash
php artisan queue:work redis --queue=metadata --timeout=660 --memory=1024
```

## Events

| Event                   | Carries                                                                                      |
|-------------------------|----------------------------------------------------------------------------------------------|
| `MetadataRefreshed`     | `changedSettings` (names only, none when nothing changed), `metadataVersion`, `trustChanged` |
| `MetadataRefreshFailed` | `reason`, `failures` in a row, `nextAttemptAt`                                               |

A refresh that changes certificates also reports `KeyRetired` and `KeyAdded`, and one that moves the endpoint
`ConnectionUpdated`, before `MetadataRefreshed`. Each event's context names the connection and, for `refreshNow()`, the
acting identity you passed; a scheduled refresh has none. No event carries a certificate, a URL or the metadata. Each is
dispatched after the refresh's transaction commits; see [Events](events.md).
