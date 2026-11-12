<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * JWT time claim checks against the package's clock, at full precision; the
 * JOSE library's own time checks never decide anything.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TimeClaims
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Why the `exp`, `iat` and `nbf` claims fail, or `null`.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  \Carbon\CarbonImmutable  $now
     * @param  int  $skewSeconds
     * @param  int  $maxAgeSeconds
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    public static function check(array $claims, CarbonImmutable $now, int $skewSeconds, int $maxAgeSeconds): ?FailureReason
    {
        $expires  = self::numericDate($claims['exp'] ?? null);
        $issued   = self::numericDate($claims['iat'] ?? null);
        $notFrom  = array_key_exists('nbf', $claims) ? self::numericDate($claims['nbf']) : -INF;
        $instant  = self::instant($now);
        $lenience = $skewSeconds;

        if ($expires === null || $issued === null || $notFrom === null) {
            return FailureReason::ID_TOKEN_INVALID;
        }

        $latest  = $instant                            + $lenience;
        $expired = $instant >= $expires                + $lenience;
        $tooOld  = $instant - $issued > $maxAgeSeconds + $lenience;
        $early   = $issued            > $latest || $notFrom > $latest;

        return $expired || $tooOld || $early ? FailureReason::ASSERTION_EXPIRED : null;
    }

    /**
     * Read a NumericDate in seconds, or `null` when it is not a JSON number.
     *
     * @param  mixed  $value
     * @return ?float
     */
    public static function numericDate(mixed $value): ?float
    {
        return is_int($value) || is_float($value) ? $value : null;
    }

    /**
     * The instant in seconds since the epoch, to the microsecond.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @return float
     */
    public static function instant(CarbonImmutable $now): float
    {
        return (float) $now->format('U.u');
    }
}
