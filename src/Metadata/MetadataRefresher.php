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
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\MetadataReader;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;

/**
 * Refreshes SAML connections' certificates and endpoints from their identity
 * provider's metadata, on a schedule and when an administrator asks
 * (`refreshNow()`) (SSO-2.8, SSO-10.3, SSO-11.12).
 *
 * The schedule (`sso:metadata:refresh`) lists the connections due
 * (`dueConnectionIds()`) and queues a `RefreshConnectionMetadata` job for each,
 * which calls `refreshQueued()`, so a large aggregate is fetched and checked on
 * a queue whose workers are sized for it; with `--sync`, the command refreshes
 * them itself (`refreshDue()`).
 *
 * A connection refreshes while `sso.features.metadata_refresh` is on, it is a
 * SAML connection, its `metadata_refresh` setting is on and its `metadata_url`
 * is a valid `https` URL. It is due while its `metadata_refresh_at` is unset or
 * not after now and no claim on it holds (`metadata_claimed_until` unset or not
 * after now); the due connections are read on the write connection in chunks of
 * `CHUNK_SIZE`, by keyset on their id. A queued refresh reads its connection
 * again and is `skipped` when it is no longer due, refreshes or exists. An
 * administrator's refresh skips the backoff, never a claim another server
 * holds, and counts against the connection's metadata limit
 * (`sso.rate_limits.metadata`) before anything is claimed or fetched: past it,
 * it is `rate_limited` with the seconds until the window ends.
 *
 * Each refresh, outside any transaction:
 *
 * 1. reads the connection's identity provider signing certificates and its
 *    metadata signing anchors, after the connection itself, so all three are
 *    the snapshot the refresh is judged against, and
 * 2. claims the connection with one conditional update, until now plus
 *    `claim_seconds` and with a fresh random token (`RefreshClaims`, answering
 *    a `RefreshClaim`), only while no claim holds and its metadata version is
 *    still the one read; no row updated is `skipped` for the schedule and
 *    `in_progress` for an administrator, with nothing else done;
 * 3. fetches the saved `metadata_url` through the package's fetcher as a
 *    metadata request held to `sso.metadata.max_bytes` (SSO-2.9), never the
 *    fetcher's own cap, and reads it for the pinned `idp_entity_id` with the
 *    anchors (`Protocols\Saml2\Library\MetadataReader`), noting the moment it
 *    validated;
 * 4. applies it, or records the failure, in one transaction that locks the
 *    connection and compares the claim and the snapshot (`MetadataApplier`).
 *
 * A refused or failed fetch is `fetch_refused` or `fetch_failed` (a response
 * that is not `2xx` or is larger than the cap included), and metadata refused
 * is its reader's reason. Each refresh that did not apply is logged as a
 * warning, through the sanitising logger, with its reason and the fetch's
 * status alone, never the URL, the response or the metadata.
 *
 * Every entry refuses to run inside a transaction on the storage connection (a
 * `LogicException`), since a refresh fetches before it writes. A database error
 * propagates (SSO-11.4) and stops a scheduled run. It asks no freshness: the
 * refresh is a system job, which an administrator switched on, and an
 * administrator's refresh does no more than a scheduled one would, but always
 * names the administrator. It holds the lookup, the claims, the fetcher, the
 * reader, the applier, the limiter, the clock and the logger, none of which
 * keeps anything of one run for the next (SSO-11.2); resolve it per run.
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
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaims  $claims
     * @param  \SineMacula\Laravel\Sso\Contracts\Fetcher  $fetcher
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Library\MetadataReader  $reader
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataApplier  $applier
     * @param  \SineMacula\Laravel\Sso\Contracts\AttemptLimiter  $limiter
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \Psr\Log\LoggerInterface  $logger
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** Finds an administrator's connection, on the write connection. */
        private ConnectionFinder $connections,

        /** Snapshots and claims a connection's refresh. */
        private RefreshClaims $claims,

        /** Fetches the metadata URL. */
        private Fetcher $fetcher,

        /** Reads the metadata for the pinned entity. */
        private MetadataReader $reader,

        /** Writes the refresh or its failure under the connection's lock. */
        private MetadataApplier $applier,

        /** Limits how often an administrator refreshes a connection's metadata. */
        private AttemptLimiter $limiter,

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
        return array_map(fn (Connection $connection): RefreshResult => $this->refresh($connection, null, false), $this->due());
    }

    /**
     * The ids of the connections whose refresh is due and that refresh, in id
     * order, for the schedule to queue a refresh of each.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function dueConnectionIds(): array
    {
        return array_map(static fn (Connection $connection): string => $connection->id, $this->due());
    }

    /**
     * Refresh the connection a queued job names, read again: `skipped` when it
     * is gone, no longer refreshes or is no longer due.
     *
     * @param  string  $connectionId
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function refreshQueued(string $connectionId): RefreshResult
    {
        StorageConnection::assertNoTransaction(self::IN_TRANSACTION);

        $connection = Connection::query()->useWritePdo()->whereKey($connectionId)->first();

        return $this->isStillDue($connection, $connectionId) ? $this->refresh($connection, null, false) : RefreshResult::skipped($connectionId);
    }

    /**
     * Refresh the tenant's connection now, whatever its backoff, for the
     * administrator who asked, once it is counted against the connection's
     * metadata limit.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function refreshNow(string $tenantId, string $connectionId, ActingIdentity $actor): RefreshResult
    {
        StorageConnection::assertNoTransaction(self::IN_TRANSACTION);

        $connection = $this->connections->find($tenantId, $connectionId);

        if ($connection === null) {
            return RefreshResult::refused(FailureReason::CONNECTION_NOT_FOUND);
        }

        if (!Features::enabled(Feature::METADATA_REFRESH) || !self::refreshes($connection)) {
            return RefreshResult::refused(FailureReason::FEATURE_DISABLED, $connection->id);
        }

        $attempt = $this->limiter->attempt(AttemptSubject::metadata($connection->id));

        return $attempt->retryAfter !== null ? RefreshResult::rateLimited($connection->id, $attempt->retryAfter) : $this->refresh($connection, $actor, true);
    }

    /**
     * Snapshot and claim the connection as read, fetch and read its metadata,
     * and apply it or record the failure; log a refresh that did not apply.
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
        $claim = $this->claims->claim($connection);

        if ($claim === null) {
            return $asked ? RefreshResult::inProgress($connection->id) : RefreshResult::skipped($connection->id);
        }

        $fetched  = $this->fetcher->fetch(FetchRequest::metadata(self::setting($connection, Saml2Setting::METADATA_URL), $this->reader->maxBytes()));
        $metadata = $fetched->isSuccessful() ? $this->read($connection, (string) $fetched->body(), $claim->anchors) : null;

        // The moment the document was validated, read once the reader is done
        $result = $metadata !== null && $metadata->isRead()
            ? $this->applier->apply($claim, $metadata, $this->clock->now(), $actor)
            : $this->applier->fail($claim, $metadata->reason ?? self::fetchFailure($fetched), $actor);

        if (!$result->isRefreshed()) {
            $this->logger->warning('sso.metadata.refresh_' . $result->outcome->value, ['reason' => $result->reason?->value, 'fetch_status' => $fetched->status->value]);
        }

        return $result;
    }

    /**
     * The fetched metadata of the connection's pinned entity, read with its
     * anchors' certificates, its current binding preferred.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $xml
     * @param  list<string>  $anchors
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata
     *
     * @throws \InvalidArgumentException
     */
    private function read(Connection $connection, #[\SensitiveParameter] string $xml, array $anchors): IdpMetadata
    {
        return $this->reader->read($xml, self::setting($connection, Saml2Setting::IDP_ENTITY_ID), $anchors, self::setting($connection, Saml2Setting::SSO_BINDING));
    }

    /**
     * Whether the connection a queued job names is still there with exactly
     * that id, refreshes, and is due and unclaimed by now.
     *
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $connectionId
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-assert-if-true !null $connection
     */
    private function isStillDue(?Connection $connection, string $connectionId): bool
    {
        if ($connection?->id !== $connectionId || !Features::enabled(Feature::METADATA_REFRESH) || !self::refreshes($connection)) {
            return false;
        }

        $now = $this->clock->now();

        return ($connection->metadata_refresh_at ?? $now) <= $now && ($connection->metadata_claimed_until ?? $now) <= $now;
    }

    /**
     * Every SAML connection whose refresh is due and unclaimed and that
     * refreshes, in id order, read in chunks; none while the refresh is off.
     *
     * @return list<\SineMacula\Laravel\Sso\Models\Connection>
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function due(): array
    {
        StorageConnection::assertNoTransaction(self::IN_TRANSACTION);

        if (!Features::enabled(Feature::METADATA_REFRESH)) {
            return [];
        }

        $due   = [];
        $after = null;

        do {

            $chunk = $this->dueAfter($after);
            $due   = [...$due, ...array_values(array_filter($chunk, self::refreshes(...)))];
            $after = $chunk === [] ? null : $chunk[count($chunk) - 1]->id;
        } while (count($chunk) === self::CHUNK_SIZE);

        return $due;
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
