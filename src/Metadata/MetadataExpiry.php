<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Whether what was fetched for a connection has stopped being usable (SSO-2.8):
 * settings from metadata whose `validUntil` has passed, or whose last validated
 * fetch is older than the stale limit, are not used, and the connection fails
 * with `metadata_expired` until it recovers.
 *
 * Every validated fetched resource counts from its own validated fetch, and the
 * connection expires at the earliest of them, whether or not its refresh is
 * scheduled: turning the schedule off never means unlimited trust, only an
 * explicit `stale_limit_seconds` of 0 does.
 *
 * - The document a refresh wrote, or a fetched import's save
 *   (`metadata_fetched_at` set): the earlier of its `metadata_valid_until` (the
 *   earliest applicable `validUntil` found, an enclosing aggregate's included)
 *   and its last validated fetch (the moment the fetched document was
 *   validated, stamped as `metadata_fetched_at`) plus
 *   `MetadataSettings::staleLimitSeconds()`, when there is a limit.
 * - An OIDC connection's JWKS (`jwks_fetched_at` set, which a refresh and an
 *   unknown-`kid` refetch both stamp): its last validated fetch plus the same
 *   limit. A committed refetch resets this one alone, never the document's.
 *
 * A connection with nothing fetched yet has no deadline: settings and keys
 * saved by hand, metadata given as XML among them, are used as they stand until
 * the first fetch of each resource stamps it. Settings saved from a fetched
 * import count from that fetch, since `Connections\ImportSaver::save()` stamps
 * what the proposal carries. An expired connection recovers through a scheduled
 * refresh or an administrator's (`MetadataRefresher::refreshNow()`), which for
 * a connection saved by hand with no document refreshes its keys alone from the
 * saved `jwks_uri`, or through a fetched import saved again; never through a
 * callback: the driver refuses it before any key is read, so a sign-in cannot
 * fetch its way back.
 *
 * A refresh applies the same rule when it commits (`hasExpired()`), from the
 * moment it validated the document, so what it writes is never already expired.
 * The rows are read as the caller holds them, so a caller deciding a flow reads
 * the connection from the write connection first (SSO-11.3); a connection given
 * only through its contract is read again there, by its id.
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

        $document = $row->metadata_fetched_at === null ? null : $this->expiryOf($row->metadata_valid_until, $row->metadata_fetched_at);
        $keys     = $row->jwks_fetched_at     === null ? null : $this->expiryOf(null, $row->jwks_fetched_at);

        return self::earliest($document, $keys);
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
