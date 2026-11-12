<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\IdTokens;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\TimeClaims;

/**
 * The ID token `auth_time` checks; never inferred from `iat`. A `max_age` of 0
 * is judged against the request start, not the callback's age.
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
     * Why the token's `auth_time` refuses it, or `null`; `$notBefore` is the
     * moment authentication must follow, if any.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  \Carbon\CarbonImmutable  $now
     * @param  int  $skewSeconds
     * @param  ?int  $maxAgeSeconds
     * @param  ?\Carbon\CarbonImmutable  $notBefore
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    public static function refusal(
        #[\SensitiveParameter] array $claims,
        CarbonImmutable $now,
        int $skewSeconds,
        ?int $maxAgeSeconds,
        ?CarbonImmutable $notBefore = null,
    ): ?FailureReason {
        $authenticatedAt = TimeClaims::numericDate($claims['auth_time'] ?? null);

        if ($authenticatedAt === null) {
            return $maxAgeSeconds === null && $notBefore === null ? null : FailureReason::ID_TOKEN_INVALID;
        }

        $instant = TimeClaims::instant($now);

        if ($authenticatedAt > $instant + $skewSeconds) {
            return FailureReason::ASSERTION_EXPIRED;
        }

        $earliest = $notBefore === null ? -INF : TimeClaims::instant($notBefore) - $skewSeconds;
        $tooOld   = $maxAgeSeconds > 0 && $instant                               - $authenticatedAt > $maxAgeSeconds + $skewSeconds;

        return $tooOld || $authenticatedAt < $earliest ? FailureReason::AUTHENTICATION_EXPIRED : null;
    }
}
