<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\IdTokens;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * The ID token `aud` and `azp` checks (OpenID Connect Core 3.1.3.7), compared
 * exactly; extra audiences must be trusted and never admit a token alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AudienceRules
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Why the token's `aud` and `azp` refuse it, or `null`.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  string  $clientId
     * @param  list<string>  $trustedAudiences
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    public static function refusal(#[\SensitiveParameter] array $claims, string $clientId, array $trustedAudiences): ?FailureReason
    {
        $audiences = is_array($claims['aud'] ?? null) ? $claims['aud'] : [$claims['aud'] ?? null];
        $others    = array_filter($audiences, static fn (mixed $audience): bool => $audience !== $clientId);
        $named     = count($others) < count($audiences);
        $trusted   = array_filter($others, static fn (mixed $audience): bool => in_array($audience, $trustedAudiences, true)) === $others;
        $party     = self::isAuthorizedParty($claims, $clientId, count($audiences));

        return $named && $trusted && $party ? null : FailureReason::AUDIENCE_MISMATCH;
    }

    /**
     * Whether `azp` is the client id, or absent from a token of one audience.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  string  $clientId
     * @param  int  $audienceCount
     * @return bool
     */
    private static function isAuthorizedParty(#[\SensitiveParameter] array $claims, string $clientId, int $audienceCount): bool
    {
        return array_key_exists('azp', $claims) ? $claims['azp'] === $clientId : $audienceCount === 1;
    }
}
