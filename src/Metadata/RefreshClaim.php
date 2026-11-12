<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * One server's claim on a connection's refresh, and the snapshot its write is
 * compared against under the lock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RefreshClaim
{
    /** @var int The bytes of randomness in a claim's token, written as hex. */
    public const int TOKEN_BYTES = 16;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $token
     * @param  array<string, mixed>  $trusted
     * @param  list<string>  $anchors
     */
    public function __construct(

        /** The connection as it was read before it was claimed. */
        public Connection $connection,

        /** The token the claim was written with. */
        public string $token,

        /** The snapshot of the connection's trust as its source reads it, comparable with `===`. */
        public array $trusted,

        /** The PEM metadata signing anchors the fetched document is verified with. */
        public array $anchors = [],
    ) {}

    /**
     * The snapshot of the certificates and anchors: each use's fingerprints,
     * sorted.
     *
     * @param  list<\SineMacula\Laravel\Sso\Keys\KeySummary>  $certificates
     * @param  list<\SineMacula\Laravel\Sso\Keys\KeySummary>  $anchors
     * @return array<string, list<string>>
     */
    public static function trustedOf(array $certificates, array $anchors): array
    {
        return [
            KeyUse::IDP_SIGNING->value      => self::sortedFingerprints($certificates),
            KeyUse::METADATA_SIGNING->value => self::sortedFingerprints($anchors),
        ];
    }

    /**
     * A fresh random token for a claim.
     *
     * @return string
     *
     * @throws \Random\RandomException
     */
    public static function token(): string
    {
        return bin2hex(random_bytes(self::TOKEN_BYTES));
    }

    /**
     * The keys' fingerprints, sorted.
     *
     * @param  list<\SineMacula\Laravel\Sso\Keys\KeySummary>  $keys
     * @return list<string>
     */
    private static function sortedFingerprints(array $keys): array
    {
        $fingerprints = array_values(array_filter(
            array_map(static fn (KeySummary $key): ?string => $key->key->fingerprint, $keys),
            static fn (?string $fingerprint): bool => $fingerprint !== null,
        ));

        sort($fingerprints, SORT_STRING);

        return $fingerprints;
    }
}
