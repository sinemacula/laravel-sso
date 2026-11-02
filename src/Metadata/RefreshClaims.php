<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Takes a server's claim on a connection's refresh (SSO-2.8, SSO-11.12),
 * outside any transaction, for any source (`MetadataSource`), with the snapshot
 * of the connection's trust the source read after the connection and before the
 * claim.
 *
 * `claim()` claims the connection with one conditional update:
 * `metadata_claimed_until` now plus `claim_seconds` and `metadata_claim_token`
 * a fresh random token, only while no claim holds (none, or one not after now)
 * and the metadata version is still the one read. It answers the
 * `RefreshClaim`, which holds the connection as read, the token and the
 * snapshot, or `null` when another server holds the claim or another refresh
 * has written since.
 *
 * It holds the settings and the clock, neither of which keeps anything of one
 * refresh for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RefreshClaims
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataSettings  $settings
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** How long a claim holds. */
        private MetadataSettings $settings,

        /** The clock the claim is read from. */
        private Clock $clock,
    ) {}

    /**
     * Claim the refresh of the connection as it was read, with the snapshot of
     * its trust and the certificates its document is verified with, read
     * before; the claim, or `null` when it was not claimed.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  array<string, mixed>  $trusted
     * @param  list<string>  $anchors
     * @return ?\SineMacula\Laravel\Sso\Metadata\RefreshClaim
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     */
    public function claim(Connection $connection, array $trusted, array $anchors = []): ?RefreshClaim
    {
        $now   = $this->clock->now();
        $at    = UtcDateTime::format($connection, $now);
        $until = UtcDateTime::format($connection, $now->addSeconds($this->settings->claimSeconds()));
        $token = RefreshClaim::token();

        $claimed = Connection::query()
            ->whereKey($connection->id)
            ->where('metadata_version', $connection->metadata_version)
            ->where(static function (Builder $free) use ($at): void {
                $free->whereNull('metadata_claimed_until')->orWhere('metadata_claimed_until', '<=', $at);
            })
            ->update(['metadata_claimed_until' => $until, 'metadata_claim_token' => $token]);

        return $claimed === 1 ? new RefreshClaim($connection, $token, $trusted, $anchors) : null;
    }
}
