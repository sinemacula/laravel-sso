<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Illuminate\Database\Eloquent\Builder;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Connections\ConnectionFinder;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;

/**
 * Refreshes connections from their identity provider through each protocol's
 * `MetadataSource`, on the schedule and when an administrator asks.
 *
 * Call outside any transaction on the storage connection; resolve it per run.
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
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return list<\SineMacula\Laravel\Sso\Metadata\RefreshResult>
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function refreshDue(ClientContext $client): array
    {
        return array_map(fn (Connection $connection): RefreshResult => $this->refresh($connection, null, $client, false), $this->due());
    }

    /**
     * The ids of the connections due a refresh, in id order, for the schedule
     * to queue.
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
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function refreshQueued(string $connectionId, ClientContext $client): RefreshResult
    {
        StorageConnection::assertNoTransaction(self::IN_TRANSACTION);

        $connection = Connection::query()->useWritePdo()->whereKey($connectionId)->first();

        return $this->isStillDue($connection, $connectionId) ? $this->refresh($connection, null, $client, false) : RefreshResult::skipped($connectionId);
    }

    /**
     * Refresh the tenant's connection now, whatever its backoff, switch or
     * expiry; a refresh the schedule would not make asks for freshness first.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function refreshNow(string $tenantId, string $connectionId, Caller $caller, ClientContext $client): RefreshResult
    {
        StorageConnection::assertNoTransaction(self::IN_TRANSACTION);

        $connection = $this->connections->find($tenantId, $connectionId);

        if ($connection === null) {
            return RefreshResult::refused(FailureReason::CONNECTION_NOT_FOUND);
        }

        $refusal = $this->refusalNow($connection, $caller);

        if ($refusal !== null) {
            return $refusal;
        }

        $attempt = $this->limiter->attempt(AttemptSubject::metadata($connection->id));

        return $attempt->retryAfter !== null ? RefreshResult::rateLimited($connection->id, $attempt->retryAfter) : $this->refresh($connection, $caller, $client, true);
    }

    /**
     * Why an administrator may not refresh the connection now, or `null` when
     * they may.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return ?\SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function refusalNow(Connection $connection, Caller $caller): ?RefreshResult
    {
        if (!$this->isRefreshable($connection)) {
            return RefreshResult::refused(FailureReason::FEATURE_DISABLED, $connection->id);
        }

        if (Features::enabled(Feature::METADATA_REFRESH) && $this->refreshes($connection)) {
            return null;
        }

        $fresh = $this->freshness->check(FreshnessOperation::CONNECTION_TRUST, $caller)->isFresh();

        return $fresh ? null : RefreshResult::refused(FailureReason::FRESHNESS_REQUIRED, $connection->id);
    }

    /**
     * Claim, fetch and write the connection through its source, and log a
     * refresh that did not apply.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  bool  $asked
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    private function refresh(Connection $connection, ?Caller $caller, ClientContext $client, bool $asked): RefreshResult
    {
        $source = $this->sourceOf($connection);
        $claim  = $source->claim($connection);

        if ($claim === null) {
            return $asked ? RefreshResult::inProgress($connection->id) : RefreshResult::skipped($connection->id);
        }

        $fetched = $source->fetch($claim);
        $result  = $source->write($claim, $fetched, $caller, $client);

        if (!$result->isRefreshed()) {
            $this->logger->warning('sso.metadata.refresh_' . $result->outcome->value, ['reason' => $result->reason?->value, 'fetch_status' => $fetched->fetchStatus->value]);
        }

        return $result;
    }

    /**
     * Whether the connection a queued job names still exists, refreshes, and is
     * due and unclaimed.
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
     * Every connection due a refresh, in id order, read in chunks; none while
     * the refresh is off.
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
            $due   = [...$due, ...$this->refreshing($chunk)];
            $after = $chunk === [] ? null : $chunk[count($chunk) - 1]->id;
        } while (count($chunk) === self::CHUNK_SIZE);

        return $due;
    }

    /**
     * Those of the chunk that refresh, in order; each source judges its own at
     * once, since a connection that never refreshes is read on every run.
     *
     * @param  list<\SineMacula\Laravel\Sso\Models\Connection>  $chunk
     * @return list<\SineMacula\Laravel\Sso\Models\Connection>
     *
     * @throws \InvalidArgumentException
     */
    private function refreshing(array $chunk): array
    {
        $refreshing = [];

        foreach (array_filter($this->sources->protocols(), $this->protocols->isAvailable(...)) as $protocol) {

            $own = array_filter($chunk, static fn (Connection $connection): bool => $connection->protocol === $protocol);

            foreach ($this->sources->for($protocol)?->refreshing(array_values($own)) ?? [] as $connection) {
                $refreshing[$connection->id] = true;
            }
        }

        return array_values(array_filter($chunk, static fn (Connection $connection): bool => isset($refreshing[$connection->id])));
    }

    /**
     * The next chunk after the id of connections with a source whose refresh is
     * due and unclaimed.
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
     * Whether the schedule refreshes the connection: its protocol is available
     * and has a source that says so.
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
     * Whether an administrator may refresh the connection, whatever its switch.
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
     * The source of the connection's protocol.
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
