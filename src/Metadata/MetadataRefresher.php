<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Illuminate\Database\Eloquent\Builder;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Connections\ConnectionFinder;
use SineMacula\Laravel\Sso\Connections\SettingRules;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyRing;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\MetadataReader;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver;

/**
 * Refreshes SAML connections' certificates and endpoints from their identity
 * provider's metadata, on a schedule (`refreshDue()`, which
 * `sso:metadata:refresh` runs) and when an administrator asks (`refreshNow()`)
 * (SSO-2.8, SSO-10.3, SSO-11.12).
 *
 * A connection refreshes while `sso.features.metadata_refresh` is on, it is a
 * SAML connection, its `metadata_refresh` setting is on and its `metadata_url`
 * is a valid `https` URL. It is due while its `metadata_refresh_at` is unset or
 * not after now and no claim on it holds (`metadata_claimed_until` unset or not
 * after now); the due connections are read on the write connection in chunks of
 * `CHUNK_SIZE`, by keyset on their id. An administrator's refresh skips the
 * backoff, never a claim another server holds.
 *
 * Each refresh, outside any transaction:
 *
 * 1. reads the connection's metadata signing anchors, after the connection
 *    itself, so both are the snapshot the refresh is judged against;
 * 2. claims the connection with one conditional update, until now plus
 *    `claim_seconds`, only while no claim holds and its metadata version is
 *    still the one read; no row updated is `skipped` for the schedule and
 *    `in_progress` for an administrator, with nothing else done;
 * 3. fetches the saved `metadata_url` through the package's fetcher as a
 *    metadata request (SSO-2.9), and reads it for the pinned `idp_entity_id`
 *    with the anchors (`Protocols\Saml2\Library\MetadataReader`);
 * 4. applies it, or records the failure, in one transaction that locks the
 *    connection and compares the snapshot (`MetadataApplier`).
 *
 * A refused or failed fetch is `fetch_refused` or `fetch_failed` (a response
 * that is not `2xx` included), and metadata refused is its reader's reason.
 * Each refresh that did not apply is logged as a warning, through the
 * sanitising logger, with its reason and the fetch's status alone, never the
 * URL, the response or the metadata.
 *
 * Both entries refuse to run inside a transaction on the storage connection (a
 * `LogicException`), since a refresh fetches before it writes. A database error
 * propagates (SSO-11.4) and stops a scheduled run. It asks no freshness: the
 * refresh is a system job, which an administrator switched on, and an
 * administrator's refresh does no more than a scheduled one would. It holds the
 * lookup, the key ring, the fetcher, the reader, the applier, the settings, the
 * clock and the logger, none of which keeps anything of one run for the next
 * (SSO-11.2); resolve it per run.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MetadataRefresher
{
    /** @var int How many due connections are read at a time. */
    public const int CHUNK_SIZE = 100;

    /** @var string Why a refresh refuses to run inside a transaction. */
    private const string IN_TRANSACTION = 'A metadata refresh runs outside any transaction on the storage connection, since it fetches before it writes.';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionFinder  $connections
     * @param  \SineMacula\Laravel\Sso\Keys\KeyRing  $keys
     * @param  \SineMacula\Laravel\Sso\Contracts\Fetcher  $fetcher
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Library\MetadataReader  $reader
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataApplier  $applier
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataSettings  $settings
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \Psr\Log\LoggerInterface  $logger
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** Finds an administrator's connection, on the write connection. */
        private ConnectionFinder $connections,

        /** The connection's metadata signing anchors. */
        private KeyRing $keys,

        /** Fetches the metadata URL. */
        private Fetcher $fetcher,

        /** Reads the metadata for the pinned entity. */
        private MetadataReader $reader,

        /** Writes the refresh or its failure under the connection's lock. */
        private MetadataApplier $applier,

        /** How long a claim holds. */
        private MetadataSettings $settings,

        /** The clock every time is read from. */
        private Clock $clock,

        /** The sanitising logger a refresh that did not apply is logged to. */
        private LoggerInterface $logger,
    ) {}

    /**
     * Refresh every connection whose refresh is due, in id order.
     *
     * @return list<\SineMacula\Laravel\Sso\Metadata\RefreshResult>
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function refreshDue(): array
    {
        StorageConnection::assertNoTransaction(self::IN_TRANSACTION);

        if (!Features::enabled(Feature::METADATA_REFRESH)) {
            return [];
        }

        $results = [];
        $after   = null;

        do {

            $chunk = $this->dueAfter($after);

            foreach (array_filter($chunk, self::refreshes(...)) as $connection) {
                $results[] = $this->refresh($connection, null, false);
            }

            $after = $chunk === [] ? null : $chunk[count($chunk) - 1]->id;
        } while (count($chunk) === self::CHUNK_SIZE);

        return $results;
    }

    /**
     * Refresh the tenant's connection now, whatever its backoff, for the
     * administrator who asked.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function refreshNow(string $tenantId, string $connectionId, ?ActingIdentity $actor = null): RefreshResult
    {
        StorageConnection::assertNoTransaction(self::IN_TRANSACTION);

        $connection = $this->connections->find($tenantId, $connectionId);

        if ($connection === null) {
            return RefreshResult::refused(FailureReason::CONNECTION_NOT_FOUND);
        }

        if (!Features::enabled(Feature::METADATA_REFRESH) || !self::refreshes($connection)) {
            return RefreshResult::refused(FailureReason::FEATURE_DISABLED, $connection->id);
        }

        return $this->refresh($connection, $actor, true);
    }

    /**
     * Claim the connection as read, fetch and read its metadata, and apply it
     * or record the failure; log a refresh that did not apply.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @param  bool  $asked
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    private function refresh(Connection $connection, ?ActingIdentity $actor, bool $asked): RefreshResult
    {
        $anchors = $this->keys->trustedCertificates($connection->id, KeyUse::METADATA_SIGNING);

        if (!$this->claimed($connection)) {
            return $asked ? RefreshResult::inProgress($connection->id) : RefreshResult::skipped($connection->id);
        }

        $fetched  = $this->fetcher->fetch(FetchRequest::metadata(self::setting($connection, Saml2Setting::METADATA_URL)));
        $metadata = $fetched->isSuccessful() ? $this->read($connection, (string) $fetched->body(), $anchors) : null;
        $result   = $metadata !== null && $metadata->isRead()
            ? $this->applier->apply($connection, self::fingerprints($anchors), $metadata, $actor)
            : $this->applier->fail($connection, $metadata->reason ?? self::fetchFailure($fetched), $actor);

        if (!$result->isRefreshed()) {
            $this->logger->warning('sso.metadata.refresh_' . $result->outcome->value, ['reason' => $result->reason?->value, 'fetch_status' => $fetched->status->value]);
        }

        return $result;
    }

    /**
     * The fetched metadata of the connection's pinned entity, read with its
     * anchors, its current binding preferred.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $xml
     * @param  list<\SineMacula\Laravel\Sso\Keys\KeySummary>  $anchors
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata
     *
     * @throws \InvalidArgumentException
     */
    private function read(Connection $connection, #[\SensitiveParameter] string $xml, array $anchors): IdpMetadata
    {
        $certificate = static fn (KeySummary $anchor): ?string => $anchor->key->certificate;
        $pems        = array_values(array_filter(array_map($certificate, $anchors), static fn (?string $pem): bool => $pem !== null));

        return $this->reader->read($xml, self::setting($connection, Saml2Setting::IDP_ENTITY_ID), $pems, self::setting($connection, Saml2Setting::SSO_BINDING));
    }

    /**
     * Claim the connection's refresh until now plus the claim, while no claim
     * holds and its metadata version is still the one read; whether it was
     * claimed.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function claimed(Connection $connection): bool
    {
        $now   = $this->clock->now();
        $at    = UtcDateTime::format($connection, $now);
        $until = UtcDateTime::format($connection, $now->addSeconds($this->settings->claimSeconds()));

        $claimed = Connection::query()
            ->whereKey($connection->id)
            ->where('metadata_version', $connection->metadata_version)
            ->where(static function (Builder $free) use ($at): void {
                $free->whereNull('metadata_claimed_until')->orWhere('metadata_claimed_until', '<=', $at);
            })
            ->update(['metadata_claimed_until' => $until]);

        return $claimed === 1;
    }

    /**
     * The next SAML connections after the id given whose refresh is due and
     * unclaimed, in id order.
     *
     * @param  ?string  $after
     * @return list<\SineMacula\Laravel\Sso\Models\Connection>
     */
    private function dueAfter(?string $after): array
    {
        $now   = UtcDateTime::format(new Connection, $this->clock->now());
        $query = Connection::query()->useWritePdo()
            ->where('protocol', Saml2Driver::NAME)
            ->where(static function (Builder $due) use ($now): void {
                $due->whereNull('metadata_refresh_at')->orWhere('metadata_refresh_at', '<=', $now);
            })
            ->where(static function (Builder $free) use ($now): void {
                $free->whereNull('metadata_claimed_until')->orWhere('metadata_claimed_until', '<=', $now);
            });

        if ($after !== null) {
            $query->where('id', '>', $after);
        }

        return array_values($query->orderBy('id')->limit(self::CHUNK_SIZE)->get()->all());
    }

    /**
     * Whether the connection's metadata refreshes: a SAML connection with
     * `metadata_refresh` on and an `https` `metadata_url`.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return bool
     */
    private static function refreshes(Connection $connection): bool
    {
        $switchedOn = $connection->protocol === Saml2Driver::NAME && ($connection->settings[Saml2Setting::METADATA_REFRESH->value] ?? null) === true;

        return $switchedOn && SettingRules::url($connection->settings[Saml2Setting::METADATA_URL->value] ?? null) === null;
    }

    /**
     * The connection's setting as a string, empty when it holds none.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting  $setting
     * @return string
     */
    private static function setting(Connection $connection, Saml2Setting $setting): string
    {
        $value = $connection->settings[$setting->value] ?? null;

        return is_string($value) ? $value : '';
    }

    /**
     * The fingerprints of the anchors.
     *
     * @param  list<\SineMacula\Laravel\Sso\Keys\KeySummary>  $anchors
     * @return list<string>
     */
    private static function fingerprints(array $anchors): array
    {
        $fingerprint = static fn (KeySummary $anchor): ?string => $anchor->key->fingerprint;

        return array_values(array_filter(array_map($fingerprint, $anchors), static fn (?string $value): bool => $value !== null));
    }

    /**
     * Why a fetch that brought no `2xx` response failed: refused, or failed.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $fetched
     * @return \SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private static function fetchFailure(FetchResult $fetched): FailureReason
    {
        return $fetched->reason ?? FailureReason::FETCH_FAILED;
    }
}
