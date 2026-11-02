<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyRing;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Takes a server's claim on a connection's metadata refresh (SSO-2.8,
 * SSO-11.12), outside any transaction, with the snapshot the refresh is later
 * judged against.
 *
 * `claim()` reads the connection's metadata signing anchors and its identity
 * provider signing certificates, after the connection itself was read, then
 * claims the connection with one conditional update: `metadata_claimed_until`
 * now plus `claim_seconds` and `metadata_claim_token` a fresh random token,
 * only while no claim holds (none, or one not after now) and the metadata
 * version is still the one read. It answers the `RefreshClaim`, which holds the
 * connection as read, the token, the sorted fingerprints of both sets and the
 * anchors' certificates for the reader, or `null` when another server holds the
 * claim or another refresh has written since.
 *
 * It holds the key ring, the settings and the clock, none of which keeps
 * anything of one refresh for the next (SSO-11.2).
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
     * @param  \SineMacula\Laravel\Sso\Keys\KeyRing  $keys
     * @param  \SineMacula\Laravel\Sso\Metadata\MetadataSettings  $settings
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** The connection's anchors and trusted certificates. */
        private KeyRing $keys,

        /** How long a claim holds. */
        private MetadataSettings $settings,

        /** The clock the claim is read from. */
        private Clock $clock,
    ) {}

    /**
     * Snapshot the connection's anchors and certificates and claim its refresh,
     * as it was read; the claim, or `null` when it was not claimed.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return ?\SineMacula\Laravel\Sso\Metadata\RefreshClaim
     *
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     */
    public function claim(Connection $connection): ?RefreshClaim
    {
        $anchors = $this->keys->trustedCertificates($connection->id, KeyUse::METADATA_SIGNING);
        $trusted = RefreshClaim::trustedOf($this->keys->trustedCertificates($connection->id), $anchors);
        $now     = $this->clock->now();
        $at      = UtcDateTime::format($connection, $now);
        $until   = UtcDateTime::format($connection, $now->addSeconds($this->settings->claimSeconds()));
        $token   = RefreshClaim::token();

        $claimed = Connection::query()
            ->whereKey($connection->id)
            ->where('metadata_version', $connection->metadata_version)
            ->where(static function (Builder $free) use ($at): void {
                $free->whereNull('metadata_claimed_until')->orWhere('metadata_claimed_until', '<=', $at);
            })
            ->update(['metadata_claimed_until' => $until, 'metadata_claim_token' => $token]);

        return $claimed === 1 ? new RefreshClaim($connection, $token, $trusted, self::certificates($anchors)) : null;
    }

    /**
     * The PEM certificates of the anchors.
     *
     * @param  list<\SineMacula\Laravel\Sso\Keys\KeySummary>  $anchors
     * @return list<string>
     */
    private static function certificates(array $anchors): array
    {
        $certificate = static fn (KeySummary $anchor): ?string => $anchor->key->certificate;

        return array_values(array_filter(array_map($certificate, $anchors), static fn (?string $pem): bool => $pem !== null));
    }
}
