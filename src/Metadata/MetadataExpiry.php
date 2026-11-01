<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Whether what a metadata refresh applied to a connection has stopped being
 * usable (SSO-2.8): settings from metadata whose `validUntil` has passed, or
 * whose last validated fetch is older than the stale limit, are not used, and
 * the connection fails with `metadata_expired` until a refresh succeeds.
 *
 * A connection that no refresh has written (`metadata_fetched_at` unset), its
 * settings entered by hand or imported once, never expires. One a refresh has
 * written expires at the earlier of its `metadata_valid_until` (the earliest
 * applicable `validUntil` the refresh found, an enclosing one included) and its
 * last validated fetch plus `MetadataSettings::staleLimitSeconds()`, when there
 * is a limit. The rows are read as the caller holds them, so a caller deciding
 * a flow reads the connection from the write connection first (SSO-11.3); a
 * connection given only through its contract is read again there, by its id.
 *
 * It holds the settings and the clock, neither of which keeps anything of one
 * request for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MetadataExpiry
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataSettings  $settings
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** The stale limit. */
        private MetadataSettings $settings,

        /** The clock expiry is judged against. */
        private Clock $clock,
    ) {}

    /**
     * Whether what a refresh applied to the connection has expired by now.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function isExpired(SsoConnection $connection): bool
    {
        $expiry = $this->expiresAt($connection);

        return $expiry !== null && $this->clock->now() >= $expiry;
    }

    /**
     * When what a refresh applied to the connection expires, or `null` when
     * nothing a refresh applied ever does.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     */
    public function expiresAt(SsoConnection $connection): ?CarbonImmutable
    {
        $row = $connection instanceof Connection ? $connection : Connection::query()->useWritePdo()->whereKey($connection->getConnectionId())->first();

        $fetched = $row?->metadata_fetched_at;

        if ($row === null || $fetched === null) {
            return null;
        }

        $limit = $this->settings->staleLimitSeconds();
        $stale = $limit === null ? null : $fetched->addSeconds($limit);

        return self::earliest($row->metadata_valid_until, $stale);
    }

    /**
     * The earlier of the two instants, either of which may be absent.
     *
     * @param  ?\Carbon\CarbonImmutable  $one
     * @param  ?\Carbon\CarbonImmutable  $other
     * @return ?\Carbon\CarbonImmutable
     */
    private static function earliest(?CarbonImmutable $one, ?CarbonImmutable $other): ?CarbonImmutable
    {
        if ($one === null || $other === null) {
            return $one ?? $other;
        }

        return $one->min($other);
    }
}
