<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\IdTokens;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\TimeClaims;

/**
 * When the person authenticated at the provider (SSO-7.4, SSO-5.10), read from
 * an `auth_time` `ClaimTypes` has typed and never inferred from `iat`, at full
 * precision against the package's clock and the skew given per call:
 *
 * - after now plus the skew is `assertion_expired`;
 * - absent, when `max_age` was asked for, is `id_token_invalid`, and absent
 *   otherwise stays unknown;
 * - more than `max_age` plus the skew before now is `authentication_expired`;
 * - for a `reauthenticate`, more than the skew before the request started is
 *   `authentication_expired`. A request's start is kept to the whole second, so
 *   it is compared as stored.
 *
 * It holds nothing between calls (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AuthenticationTimeRules
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Why the token's `auth_time` refuses it at now with the skew, under the
     * `max_age` asked for (`null` for none) and the moment a `reauthenticate`
     * started (`null` for any other flow); `null` when it passes.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  \Carbon\CarbonImmutable  $now
     * @param  int  $skewSeconds
     * @param  ?int  $maxAgeSeconds
     * @param  ?\Carbon\CarbonImmutable  $reauthenticationStartedAt
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    public static function refusal(
        #[\SensitiveParameter] array $claims,
        CarbonImmutable $now,
        int $skewSeconds,
        ?int $maxAgeSeconds,
        ?CarbonImmutable $reauthenticationStartedAt = null,
    ): ?FailureReason {
        $authenticatedAt = TimeClaims::numericDate($claims['auth_time'] ?? null);

        if ($authenticatedAt === null) {
            return $maxAgeSeconds === null ? null : FailureReason::ID_TOKEN_INVALID;
        }

        $instant = TimeClaims::instant($now);

        if ($authenticatedAt > $instant + $skewSeconds) {
            return FailureReason::ASSERTION_EXPIRED;
        }

        $tooOld   = $maxAgeSeconds             !== null && $instant                                                           - $authenticatedAt > $maxAgeSeconds + $skewSeconds;
        $tooEarly = $reauthenticationStartedAt !== null && $authenticatedAt < TimeClaims::instant($reauthenticationStartedAt) - $skewSeconds;

        return $tooOld || $tooEarly ? FailureReason::AUTHENTICATION_EXPIRED : null;
    }
}
