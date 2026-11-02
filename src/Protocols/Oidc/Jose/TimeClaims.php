<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * The time claims of a JWT, checked by the package against its own clock and
 * skew, given per call (SSO-7.4, SSO-11.13, RFC 7519 §4.1): the library's own
 * time checks never decide anything.
 *
 * `check()` answers `null` when the claims pass, or why they do not:
 *
 * - `id_token_invalid`: `exp` or `iat` missing, or `exp`, `iat` or `nbf` not a
 *   JSON number (a numeric string, a boolean or an integer too large to read
 *   is not one);
 * - `assertion_expired`: now is at or after `exp` plus the skew; `nbf` or `iat`
 *   is after now plus the skew; or now is more than the maximum age plus the
 *   skew after `iat`.
 *
 * Times are compared at full precision: a fractional NumericDate is kept, and
 * now is read to the microsecond. Nothing is kept between calls, so two checks
 * with different clocks and skews in one process each see their own (SSO-11.2).
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
     * Why the claims' `exp`, `iat` and `nbf` fail at now with the skew and the
     * maximum age of `iat`, both in seconds; `null` when they pass.
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
     * The NumericDate the value holds, in seconds since the epoch, or `null`
     * when it is not a JSON number.
     *
     * @param  mixed  $value
     * @return ?float
     */
    public static function numericDate(mixed $value): ?float
    {
        return is_int($value) || is_float($value) ? $value : null;
    }

    /**
     * The instant, in seconds since the epoch, to the microsecond.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @return float
     */
    public static function instant(CarbonImmutable $now): float
    {
        return (float) $now->format('U.u');
    }
}
