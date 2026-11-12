<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\IdTokens;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\Base64Url;
use SineMacula\Laravel\Sso\Secrets\ConstantTime;

/**
 * The ID token `at_hash` check (OpenID Connect Core 3.1.3.8); an absent claim
 * passes, as the code flow allows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AccessTokenHash
{
    /** @var array<int, string> The hash of each algorithm size. */
    private const array HASHES = [256 => 'sha256', 384 => 'sha384', 512 => 'sha512'];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Why the token's `at_hash` refuses it, or `null`.
     *
     * @param  array<array-key, mixed>  $claims
     * @param  string  $accessToken
     * @param  string  $algorithm
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    public static function refusal(#[\SensitiveParameter] array $claims, #[\SensitiveParameter] string $accessToken, string $algorithm): ?FailureReason
    {
        if (!array_key_exists('at_hash', $claims)) {
            return null;
        }

        $given    = $claims['at_hash'];
        $expected = self::of($accessToken, $algorithm);

        return is_string($given) && $expected !== null && ConstantTime::equals($expected, $given) ? null : FailureReason::AT_HASH_MISMATCH;
    }

    /**
     * Compute the `at_hash` of the access token, or `null` for an algorithm
     * whose size names no hash.
     *
     * @param  string  $accessToken
     * @param  string  $algorithm
     * @return ?string
     */
    public static function of(#[\SensitiveParameter] string $accessToken, string $algorithm): ?string
    {
        $hash = self::HASHES[substr($algorithm, 2)] ?? null;

        if ($hash === null) {
            return null;
        }

        $digest = hash($hash, $accessToken, true);

        return Base64Url::encode(substr($digest, 0, intdiv(strlen($digest), 2)));
    }
}
