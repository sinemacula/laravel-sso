<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use SineMacula\Laravel\Sso\Keys\Enums\KeyType;

/**
 * The algorithms a `private_key_jwt` client assertion may be signed with, per
 * key type; the pinned algorithm is never negotiated or retried.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ClientAssertionAlgorithm
{
    /** @var string RSA-PSS over SHA-256, an RSA key's default. */
    public const string PS256 = 'PS256';

    /** @var string RSA PKCS #1 v1.5 over SHA-256, for providers that refuse PSS. */
    public const string RS256 = 'RS256';

    /** @var string ECDSA on P-256 over SHA-256, a P-256 key's only algorithm. */
    public const string ES256 = 'ES256';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The algorithms a key of the type may sign with, its default first.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @return list<string>
     */
    public static function allowedFor(KeyType $type): array
    {
        return match ($type) {
            KeyType::RSA => [self::PS256, self::RS256],
            KeyType::EC  => [self::ES256],
        };
    }

    /**
     * Whether a key of the type can sign under the pinned algorithm; `null`
     * means the key's default.
     *
     * @param  ?string  $pinned
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @return bool
     */
    public static function fits(?string $pinned, KeyType $type): bool
    {
        return $pinned === null || in_array($pinned, self::allowedFor($type), true);
    }
}
