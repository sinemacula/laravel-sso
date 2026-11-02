<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting;

/**
 * Whether what a metadata refresh applied to a connection has stopped being
 * usable (SSO-2.8): settings from metadata whose `validUntil` has passed, or
 * whose last validated fetch is older than the stale limit, are not used, and
 * the connection fails with `metadata_expired` until a refresh succeeds.
 *
 * Each resource counts from its own validated fetch, and the connection expires
 * at the earliest of them:
 *
 * - the document a refresh wrote (`metadata_fetched_at` set): the earlier of
 *   its `metadata_valid_until` (the earliest applicable `validUntil` the
 *   refresh found, an enclosing aggregate's included) and its last validated
 *   fetch (the moment the fetched document was validated, which the refresh
 *   stamps as `metadata_fetched_at`) plus
 *   `MetadataSettings::staleLimitSeconds()`, when there is a limit;
 * - an OIDC connection's JWKS, once a refresh has written the connection or
 *   while its `metadata_refresh` setting is on: its last validated fetch
 *   (`jwks_fetched_at`, which a refresh and an unknown-`kid` refetch both
 *   stamp) plus the same limit. So keys a refetch fetched for a connection
 *   whose refresh is on but has not yet succeeded, or has failed since an
 *   issuer change, age out too, and a connection whose JWKS is already over the
 *   limit when its refresh is switched on is refused until the first refresh
 *   succeeds.
 *
 * A connection with neither, its settings entered by hand or imported once and
 * its refresh off, never expires, whatever an unknown-`kid` refetch stamped:
 * its keys have no refresh that could recover them, and a refetch happens only
 * for an unknown `kid`. A refresh applies the same rule when it commits
 * (`hasExpired()`), from the moment it validated the document, so what it
 * writes is never already expired. The rows are read as the caller holds them,
 * so a caller deciding a flow reads the connection from the write connection
 * first (SSO-11.3); a connection given only through its contract is read again
 * there, by its id.
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
     * When what the connection was refreshed with expires, or `null` when
     * nothing does.
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

        $fetched  = $row->metadata_fetched_at;
        $document = $fetched === null ? null : $this->expiryOf($row->metadata_valid_until, $fetched);

        return self::earliest($document, $this->keysExpiry($row));
    }

    /**
     * When metadata validated at the instant given, with the `validUntil`
     * given, expires: the earlier of the `validUntil` and that instant plus the
     * stale limit, when there is one; `null` when neither applies.
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
     * Whether metadata validated at the instant given, with the `validUntil`
     * given, has expired by now: what a refresh checks again when it commits.
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
     * When the connection's JWKS expires: the limit after its validated fetch,
     * once a refresh has written the connection or while its refresh is on.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $row
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     */
    private function keysExpiry(Connection $row): ?CarbonImmutable
    {
        $fetched    = $row->jwks_fetched_at;
        $refreshing = $row->metadata_fetched_at !== null || ($row->settings[OidcSetting::METADATA_REFRESH->value] ?? null) === true;

        return $fetched !== null && $refreshing ? $this->expiryOf(null, $fetched) : null;
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
