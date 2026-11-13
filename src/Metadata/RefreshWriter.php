<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Administration\MetadataEvents;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Secrets\ConstantTime;

/**
 * Writes a refresh of any source: the lock, the compare and set against the
 * claim, the bookkeeping and the events.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RefreshWriter
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Administration\MetadataEvents  $events
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataSettings  $settings
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\Sso\Freshness\FreshnessGate  $freshness
     */
    public function __construct(

        /** Reports the refresh or its failure. */
        private MetadataEvents $events,

        /** The refresh interval and the backoff. */
        private MetadataSettings $settings,

        /** The clock every time is read from. */
        private Clock $clock,

        /** Asks an administrator's refresh whether its caller is fresh. */
        private FreshnessGate $freshness,
    ) {}

    /**
     * Run the work on the claimed connection, locked, unless the claim was
     * lost, the trust snapshot the source reads again under the lock changed,
     * or the claim asks freshness and the caller is stale.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @param  \Closure(\SineMacula\Laravel\Sso\Models\Connection): array<string, mixed>  $lockedTrust
     * @param  \Closure(\SineMacula\Laravel\Sso\Models\Connection): \SineMacula\Laravel\Sso\Metadata\RefreshResult  $work
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \Throwable
     */
    public function locked(RefreshClaim $claim, \Closure $lockedTrust, \Closure $work, ?Caller $caller, ClientContext $client): RefreshResult
    {
        return DB::connection(StorageConnection::name())->transaction(function () use ($claim, $lockedTrust, $work, $caller, $client): RefreshResult {

            $locked  = self::lockedConnection($claim);
            $trusted = $locked === null ? null : $lockedTrust($locked);

            // Asked once every row is locked, and before a conflict is reported
            if ($locked !== null && $claim->asksFreshness && !$this->freshness->check(FreshnessOperation::CONNECTION_TRUST, $caller)->isFresh()) {
                return $this->stale($locked, $claim);
            }

            if ($locked === null || !self::isUnchanged($locked, $claim) || $trusted !== $claim->trusted) {
                return $this->conflict($claim, $locked, $caller, $client);
            }

            return $work($locked);
        });
    }

    /**
     * Record a failed refresh: one more failure in a row, the next after the
     * backoff, the claim released and the last good settings kept.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     */
    public function failed(Connection $locked, FailureReason $reason, ?Caller $caller, ClientContext $client): RefreshResult
    {
        $failures = $locked->metadata_refresh_failures + 1;
        $next     = $this->clock->now()->addSeconds($this->settings->backoffSeconds($failures));

        $locked->forceFill([
            'metadata_refresh_failures' => $failures,
            'metadata_refresh_at'       => $next,
            'metadata_claimed_until'    => null,
            'metadata_claim_token'      => null,
        ])->save();

        $this->events->refreshFailed($locked, $reason, $failures, $next, $caller, $client);

        return RefreshResult::failed($locked->id, $reason, $failures, $next);
    }

    /**
     * Write the source's attributes and the refresh's bookkeeping in one save,
     * stamping the moment the document was validated, never the commit.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  array<string, mixed>  $attributes
     * @param  \Carbon\CarbonImmutable  $validatedAt
     * @param  ?\Carbon\CarbonImmutable  $validUntil
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function succeeded(Connection $locked, array $attributes, CarbonImmutable $validatedAt, ?CarbonImmutable $validUntil = null): void
    {
        $locked->forceFill([
            ...$attributes,
            ...self::bookkeeping($locked),
            'metadata_fetched_at'  => $validatedAt,
            'metadata_valid_until' => $validUntil,
            'metadata_refresh_at'  => $this->nextRefreshAt($this->clock->now(), $validUntil),
        ])->save();
    }

    /**
     * Write the bookkeeping of a refresh that fetched keys alone, leaving the
     * document's stamps as they were.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  array<string, mixed>  $attributes
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function keysSucceeded(Connection $locked, array $attributes): void
    {
        $locked->forceFill([
            ...$attributes,
            ...self::bookkeeping($locked),
            'metadata_refresh_at' => $this->nextRefreshAt($this->clock->now(), $locked->metadata_valid_until),
        ])->save();
    }

    /**
     * Report the locked connection refreshed, naming the settings the source
     * changed, and answer it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  list<string>  $changed
     * @param  bool  $trustChanged
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     */
    public function refreshed(Connection $locked, array $changed, bool $trustChanged, ?Caller $caller, ClientContext $client): RefreshResult
    {
        $this->events->refreshed($locked, $changed, $locked->metadata_version, $trustChanged, $caller, $client);

        return RefreshResult::refreshed($locked->id, $changed, $locked->metadata_version, $trustChanged);
    }

    /**
     * The refresh lost its claim or to a change: write nothing and report the
     * connection as the winner left it.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     */
    private function conflict(RefreshClaim $claim, ?Connection $locked, ?Caller $caller, ClientContext $client): RefreshResult
    {
        if ($locked !== null) {
            $this->events->refreshFailed($locked, FailureReason::METADATA_CONFLICT, $locked->metadata_refresh_failures, $locked->metadata_refresh_at, $caller, $client);
        }

        return RefreshResult::conflict($claim->connection->id);
    }

    /**
     * Release the claim of a caller found stale under the lock, if it is still
     * this refresh's, writing nothing else and reporting nothing.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     */
    private function stale(Connection $locked, RefreshClaim $claim): RefreshResult
    {
        if (self::isOwned($locked, $claim)) {
            $locked->forceFill(['metadata_claimed_until' => null, 'metadata_claim_token' => null])->save();
        }

        return RefreshResult::refused(FailureReason::FRESHNESS_REQUIRED, $locked->id);
    }

    /**
     * The next refresh after the interval, or at the `validUntil` if sooner.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?\Carbon\CarbonImmutable  $validUntil
     * @return \Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     */
    private function nextRefreshAt(CarbonImmutable $now, ?CarbonImmutable $validUntil): CarbonImmutable
    {
        $next = $now->addSeconds($this->settings->refreshIntervalSeconds());

        return $validUntil === null ? $next : $next->min($validUntil);
    }

    /**
     * What every successful refresh writes, whatever it fetched.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @return array<string, mixed>
     */
    private static function bookkeeping(Connection $locked): array
    {
        return [
            'metadata_version'          => $locked->metadata_version + 1,
            'metadata_refresh_failures' => 0,
            'metadata_claimed_until'    => null,
            'metadata_claim_token'      => null,
        ];
    }

    /**
     * Whether the locked connection still holds the claim's token and the
     * metadata and trust versions the refresh read.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @return bool
     */
    private static function isUnchanged(Connection $locked, RefreshClaim $claim): bool
    {
        $claimed = $claim->connection;

        return self::isOwned($locked, $claim) && $locked->metadata_version === $claimed->metadata_version && $locked->trust_version === $claimed->trust_version;
    }

    /**
     * Whether the locked connection still holds the claim's token.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @return bool
     */
    private static function isOwned(Connection $locked, RefreshClaim $claim): bool
    {
        return is_string($locked->metadata_claim_token) && ConstantTime::equals($locked->metadata_claim_token, $claim->token);
    }

    /**
     * The claimed connection read again under lock, or `null` when it is gone.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @return ?\SineMacula\Laravel\Sso\Models\Connection
     */
    private static function lockedConnection(RefreshClaim $claim): ?Connection
    {
        $id    = $claim->connection->id;
        $found = Connection::query()->useWritePdo()->whereKey($id)->lockForUpdate()->first();

        return $found?->id === $id ? $found : null;
    }
}
