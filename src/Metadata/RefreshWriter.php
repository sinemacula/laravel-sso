<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Administration\MetadataEvents;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Writes a refresh of any source (SSO-2.8, SSO-2.13): the transaction, the
 * lock, the compare and set, the bookkeeping and the events every source shares
 * (`MetadataSource`), so a SAML metadata refresh and an OIDC discovery and JWKS
 * refresh are judged and recorded alike.
 *
 * `locked()` runs a source's write in one transaction on the storage connection
 * whose first statement locks the connection's row, the only lock a refresh
 * takes. The locked connection must still be there, still hold the claim's
 * token (no other server took the claim over once it expired), have the
 * metadata version and the trust version the refresh read before it claimed,
 * and give, read again under the lock by the source, exactly the claim's
 * snapshot of its trust. Anything else is `conflict` (`metadata_conflict`): the
 * refresh writes nothing, not even its claim, and `MetadataRefreshFailed`
 * reports the connection as the winner left it.
 *
 * `failed()` records a failure on the locked connection: the failures in a row
 * raised, the next refresh due after the backoff for that many, the claim and
 * its token released, the last good settings kept, and `MetadataRefreshFailed`
 * reported. `succeeded()` writes the source's attributes with the refresh's
 * bookkeeping in one save: the metadata version raised, `metadata_fetched_at`
 * the moment the fetched document was validated (never the later commit),
 * `metadata_valid_until` its `validUntil`, the failures reset, the claim and
 * its token released, and the next refresh due after the refresh interval,
 * never after the `validUntil`; `refreshed()` then reports `MetadataRefreshed`
 * with the settings the source changed and whether its trust changed.
 *
 * Every event is dispatched after the transaction commits (SSO-10.5). A
 * database error propagates (SSO-11.4). It holds the reporter, the settings and
 * the clock, none of which keeps anything of one refresh for the next
 * (SSO-11.2).
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
     */
    public function __construct(

        /** Reports the refresh or its failure. */
        private MetadataEvents $events,

        /** The refresh interval and the backoff. */
        private MetadataSettings $settings,

        /** The clock every time is read from. */
        private Clock $clock,
    ) {}

    /**
     * Run the work on the connection the claim holds, locked, unless the claim
     * was lost or the connection or its trust changed meanwhile: the source
     * reads its snapshot of the locked connection's trust again, with locking
     * reads, through the closure given.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @param  \Closure(\SineMacula\Laravel\Sso\Models\Connection): array<string, mixed>  $lockedTrust
     * @param  \Closure(\SineMacula\Laravel\Sso\Models\Connection): \SineMacula\Laravel\Sso\Metadata\RefreshResult  $work
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \Throwable
     */
    public function locked(RefreshClaim $claim, \Closure $lockedTrust, \Closure $work, ?ActingIdentity $actor): RefreshResult
    {
        return DB::connection(StorageConnection::name())->transaction(function () use ($claim, $lockedTrust, $work, $actor): RefreshResult {

            $locked = self::lockedConnection($claim);

            if ($locked === null || !self::isUnchanged($locked, $claim) || $lockedTrust($locked) !== $claim->trusted) {
                return $this->conflict($claim, $locked, $actor);
            }

            return $work($locked);
        });
    }

    /**
     * Record a failed refresh of the locked connection: one more failure in a
     * row, the next refresh after the backoff, the claim and its token
     * released.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     */
    public function failed(Connection $locked, FailureReason $reason, ?ActingIdentity $actor): RefreshResult
    {
        $failures = $locked->metadata_refresh_failures + 1;
        $next     = $this->clock->now()->addSeconds($this->settings->backoffSeconds($failures));

        $locked->forceFill([
            'metadata_refresh_failures' => $failures,
            'metadata_refresh_at'       => $next,
            'metadata_claimed_until'    => null,
            'metadata_claim_token'      => null,
        ])->save();

        $this->events->refreshFailed($locked, $reason, $failures, $next, $actor);

        return RefreshResult::failed($locked->id, $reason, $failures, $next);
    }

    /**
     * Write the source's attributes and the refresh's bookkeeping to the locked
     * connection, in one save: the metadata version raised, the validated fetch
     * and `validUntil`, the failures reset, the claim released and the next
     * refresh due.
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
            'metadata_version'          => $locked->metadata_version + 1,
            'metadata_fetched_at'       => $validatedAt,
            'metadata_valid_until'      => $validUntil,
            'metadata_refresh_at'       => $this->nextRefreshAt($this->clock->now(), $validUntil),
            'metadata_refresh_failures' => 0,
            'metadata_claimed_until'    => null,
            'metadata_claim_token'      => null,
        ])->save();
    }

    /**
     * Report the locked connection refreshed, naming the settings the source
     * changed, and answer it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  list<string>  $changed
     * @param  bool  $trustChanged
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     */
    public function refreshed(Connection $locked, array $changed, bool $trustChanged, ?ActingIdentity $actor): RefreshResult
    {
        $this->events->refreshed($locked, $changed, $locked->metadata_version, $trustChanged, $actor);

        return RefreshResult::refreshed($locked->id, $changed, $locked->metadata_version, $trustChanged);
    }

    /**
     * The refresh lost its claim or to a change made while it fetched, and
     * writes nothing; the failure is reported with the connection as the winner
     * left it.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshClaim  $claim
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return \SineMacula\Laravel\Sso\Metadata\RefreshResult
     *
     * @throws \InvalidArgumentException
     */
    private function conflict(RefreshClaim $claim, ?Connection $locked, ?ActingIdentity $actor): RefreshResult
    {
        if ($locked !== null) {
            $this->events->refreshFailed($locked, FailureReason::METADATA_CONFLICT, $locked->metadata_refresh_failures, $locked->metadata_refresh_at, $actor);
        }

        return RefreshResult::conflict($claim->connection->id);
    }

    /**
     * When the next refresh is due after one that succeeded now: after the
     * refresh interval, or at the `validUntil` when that comes first.
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
        $owned   = $locked->metadata_claim_token === $claim->token;

        return $owned && $locked->metadata_version === $claimed->metadata_version && $locked->trust_version === $claimed->trust_version;
    }

    /**
     * The connection the claim holds read again, locked for update until the
     * transaction ends, or `null` when it is gone.
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
