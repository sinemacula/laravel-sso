<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Illuminate\Database\Eloquent\Builder;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Connections\ConnectionFinder;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;

/**
 * Refreshes connections from their identity provider, on a schedule and when an
 * administrator asks (`refreshNow()`) (SSO-2.8, SSO-10.3, SSO-11.12): a SAML
 * connection's certificates and endpoints from its metadata, and an OIDC
 * connection's discovery document and JWKS, each through its protocol's
 * `MetadataSource` (`MetadataSources`).
 *
 * The schedule (`sso:metadata:refresh`) lists the connections due
 * (`dueConnectionIds()`) and queues a `RefreshConnectionMetadata` job for each,
 * which calls `refreshQueued()`, so a large aggregate is fetched and checked on
 * a queue whose workers are sized for it; with `--sync`, the command refreshes
 * them itself (`refreshDue()`).
 *
 * The schedule refreshes a connection while `sso.features.metadata_refresh` is
 * on, its protocol is available (`ProtocolManager::isAvailable()`, so a
 * protocol switched off fetches nothing and writes nothing) and has a source,
 * and its source finds it refreshes (`MetadataSource::refreshes()`: its own
 * switch is on and what it fetches is a URL the package may fetch). It is due
 * while its `metadata_refresh_at` is unset or not after now and no claim on it
 * holds (`metadata_claimed_until` unset or not after now), expired or not, so
 * the schedule recovers a connection past its stale limit; the due connections
 * are read on the write connection in chunks of `CHUNK_SIZE`, by keyset on
 * their id. A queued refresh reads its connection again and is `skipped` when
 * it is no longer due, refreshes or exists.
 *
 * An administrator's refresh is what recovers a connection the schedule does
 * not, so it depends on neither `sso.features.metadata_refresh` nor the
 * connection's own switch, and works on one already expired: it needs only its
 * protocol available and what it fetches to be a URL the package may fetch
 * (`MetadataSource::isRefreshable()`), or it is `feature_disabled`, with
 * nothing fetched. Where the schedule would not refresh the connection, its
 * switch or the feature being off, the refresh changes what the schedule was
 * told to leave alone, so `sso.connection.trust` is asked first, and `stale` is
 * `freshness_required` (SSO-2.12). It skips the backoff, never a claim another
 * server holds, and counts against the connection's metadata limit
 * (`sso.rate_limits.metadata`) before anything is claimed or fetched: past it,
 * it is `rate_limited` with the seconds until the window ends.
 *
 * Each refresh, outside any transaction, has its source:
 *
 * 1. snapshot the connection's trust, after the connection itself was read, and
 *    claim the connection with one conditional update, until now plus
 *    `claim_seconds` and with a fresh random token (`RefreshClaims`, answering
 *    a `RefreshClaim`), only while no claim holds and its metadata version is
 *    still the one read; no row updated is `skipped` for the schedule and
 *    `in_progress` for an administrator, with nothing else done;
 * 2. fetch and validate what it refreshes from, noting the moment it
 *    validated (`FetchedMetadata`);
 * 3. write it, or record the failure, in one transaction that locks the
 *    connection and compares the claim and the snapshot (`RefreshWriter`).
 *
 * Each refresh that did not apply is logged as a warning, through the
 * sanitising logger, with its reason and the fetch's status alone, never the
 * URL, the response or the document.
 *
 * Every entry refuses to run inside a transaction on the storage connection (a
 * `LogicException`), since a refresh fetches before it writes. A database error
 * propagates (SSO-11.4) and stops a scheduled run. A scheduled refresh asks no
 * freshness, being a system job an administrator left on, and neither does an
 * administrator's refresh of a connection the schedule would refresh too, which
 * does no more than the schedule would, but always names the administrator. It
 * holds the lookup, the protocols, the sources, the limiter, the freshness
 * gate, the clock and the logger, none of which keeps anything of one run for
 * the next (SSO-11.2); resolve it per run.
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
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataSources  $sources
     * @param  \SineMacula\Laravel\Sso\Contracts\AttemptLimiter  $limiter
     * @param  \SineMacula\Laravel\Sso\Freshness\FreshnessGate  $freshness
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \Psr\Log\LoggerInterface  $logger
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** Finds an administrator's connection, on the write connection. */
        private ConnectionFinder $connections,

        /** Whether a connection's protocol is available. */
        private ProtocolManager $protocols,

        /** What each protocol refreshes, how it fetches and how it writes. */
        private MetadataSources $sources,

        /** Limits how often an administrator refreshes a connection's metadata. */
        private AttemptLimiter $limiter,

        /** Asks whether an administrator's authentication is fresh enough. */
        private FreshnessGate $freshness,

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
     * Refresh the tenant's connection now, for the administrator who asked,
     * whatever its backoff, its switch or the schedule's, and whether it has
     * expired or not, once a refresh the schedule would not make has asked for
     * freshness and it is counted against the connection's metadata limit.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function refreshNow(string $tenantId, string $connectionId, ActingIdentity $actor): RefreshResult
    {
        StorageConnection::assertNoTransaction(self::IN_TRANSACTION);

        $connection = $this->connections->find($tenantId, $connectionId);

        if ($connection === null) {
            return RefreshResult::refused(FailureReason::CONNECTION_NOT_FOUND);
        }

        $refusal = $this->refusalNow($connection);

        if ($refusal !== null) {
            return $refusal;
        }

        $attempt = $this->limiter->attempt(AttemptSubject::metadata($connection->id));

        return $attempt->retryAfter !== null ? RefreshResult::rateLimited($connection->id, $attempt->retryAfter) : $this->refresh($connection, $actor, true);
    }

    /**
     * Why an administrator may not refresh the connection now, or `null` when
     * they may: nothing to fetch or its protocol off, or a stale authentication
     * where the schedule would not refresh it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return ?\SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function refusalNow(Connection $connection): ?RefreshResult
    {
        if (!$this->isRefreshable($connection)) {
            return RefreshResult::refused(FailureReason::FEATURE_DISABLED, $connection->id);
        }

        if (Features::enabled(Feature::METADATA_REFRESH) && $this->refreshes($connection)) {
            return null;
        }

        return $this->freshness->check(FreshnessOperation::CONNECTION_TRUST)->isFresh() ? null : RefreshResult::refused(FailureReason::FRESHNESS_REQUIRED, $connection->id);
    }

    /**
     * Have the connection's source snapshot and claim it as read, fetch and
     * validate, and write it or record the failure; log a refresh that did not
     * apply.
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
        $source = $this->sourceOf($connection);
        $claim  = $source->claim($connection);

        if ($claim === null) {
            return $asked ? RefreshResult::inProgress($connection->id) : RefreshResult::skipped($connection->id);
        }

        $fetched = $source->fetch($claim);
        $result  = $source->write($claim, $fetched, $actor);

        if (!$result->isRefreshed()) {
            $this->logger->warning('sso.metadata.refresh_' . $result->outcome->value, ['reason' => $result->reason?->value, 'fetch_status' => $fetched->fetchStatus->value]);
        }

        return $result;
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
        if ($connection?->id !== $connectionId || !Features::enabled(Feature::METADATA_REFRESH) || !$this->refreshes($connection)) {
            return false;
        }

        $now = $this->clock->now();

        return ($connection->metadata_refresh_at ?? $now) <= $now && ($connection->metadata_claimed_until ?? $now) <= $now;
    }

    /**
     * Every connection whose refresh is due and unclaimed and that refreshes,
     * in id order, read in chunks; none while the refresh is off.
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
            $due   = [...$due, ...array_filter($chunk, $this->refreshes(...))];
            $after = $chunk === [] ? null : $chunk[count($chunk) - 1]->id;
        } while (count($chunk) === self::CHUNK_SIZE);

        return $due;
    }

    /**
     * The next connections of a protocol with a source after the id given whose
     * refresh is due and unclaimed, in id order.
     *
     * @param  ?string  $after
     * @return list<\SineMacula\Laravel\Sso\Models\Connection>
     */
    private function dueAfter(?string $after): array
    {
        $now   = UtcDateTime::format(new Connection, $this->clock->now());
        $query = Connection::query()->useWritePdo()
            ->whereIn('protocol', $this->sources->protocols())
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
     * Whether the connection refreshes: its protocol is available, and its
     * protocol's source judges that it does; never for a protocol with no
     * source.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function refreshes(Connection $connection): bool
    {
        return $this->protocols->isAvailable($connection->protocol) && $this->sources->for($connection->protocol)?->refreshes($connection) === true;
    }

    /**
     * Whether an administrator may refresh the connection: its protocol is
     * available, and its protocol's source could fetch what it refreshes from,
     * whatever its switch says.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function isRefreshable(Connection $connection): bool
    {
        return $this->protocols->isAvailable($connection->protocol) && $this->sources->for($connection->protocol)?->isRefreshable($connection) === true;
    }

    /**
     * The source of the connection's protocol, which a connection that
     * refreshes always has.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Metadata\MetadataSource
     *
     * @throws \LogicException
     */
    private function sourceOf(Connection $connection): MetadataSource
    {
        $source = $this->sources->for($connection->protocol);

        if ($source === null) {
            throw new \LogicException(sprintf('The [%s] protocol has no metadata source.', $connection->protocol));
        }

        return $source;
    }
}
