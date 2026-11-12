<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Takes a server's claim on a connection's refresh with one conditional update,
 * outside any transaction.
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
     * Claim the refresh of the connection as read, with the trust snapshot and
     * anchors read before; `null` when another server holds it or another
     * refresh has written since.
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
