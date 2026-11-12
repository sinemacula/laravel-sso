<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Whether what was fetched for a connection has passed its `validUntil` or the
 * stale limit, counted from each resource's own validated fetch.
 *
 * A caller deciding a flow passes the connection as read on the write
 * connection.
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
     * Whether what was fetched for the connection has expired by now.
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
     * When what was fetched for the connection expires, or `null` when nothing
     * does.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     */
    public function expiresAt(SsoConnection $connection): ?CarbonImmutable
    {
        $row = $connection instanceof Connection ? $connection : Connection::query()->useWritePdo()->whereKey($connection->getConnectionId())->first();

        if ($row === null) {
            return null;
        }

        $keys = $row->jwks_fetched_at === null ? null : $this->expiryOf(null, $row->jwks_fetched_at);

        return self::earliest($this->documentExpiry($row), $keys);
    }

    /**
     * The earlier of the `validUntil` and the validated instant plus the stale
     * limit; `null` when neither applies.
     *
     * @param  ?\Carbon\CarbonImmutable  $validUntil
     * @param  \Carbon\CarbonImmutable  $validatedAt
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     */
    public function expiryOf(?CarbonImmutable $validUntil, CarbonImmutable $validatedAt): ?CarbonImmutable
    {
        $limit = $this->settings->staleLimitSeconds();

        return self::earliest($validUntil, $limit === null ? null : $validatedAt->addSeconds($limit));
    }

    /**
     * Whether metadata validated at the instant has expired by now: what a
     * refresh checks again when it commits.
     *
     * @param  ?\Carbon\CarbonImmutable  $validUntil
     * @param  \Carbon\CarbonImmutable  $validatedAt
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function hasExpired(?CarbonImmutable $validUntil, CarbonImmutable $validatedAt): bool
    {
        $expiry = $this->expiryOf($validUntil, $validatedAt);

        return $expiry !== null && $this->clock->now() >= $expiry;
    }

    /**
     * When the connection's document expires: never with none fetched, or for a
     * SAML connection that holds no deadline.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $row
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     */
    private function documentExpiry(Connection $row): ?CarbonImmutable
    {
        $fetchedAt = $row->metadata_fetched_at;

        return $fetchedAt === null || !SamlRefreshRule::holdsDeadline($row) ? null : $this->expiryOf($row->metadata_valid_until, $fetchedAt);
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
