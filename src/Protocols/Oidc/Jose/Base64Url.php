<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose;

/**
 * Unpadded base64url (RFC 7515 §2, RFC 4648 §5), read strictly: only the
 * URL-safe alphabet, no padding, no whitespace, and only the canonical encoding
 * of its bytes, so a value has one spelling and two readers cannot decode it
 * differently.
 *
 * It holds nothing between calls (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Base64Url
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The bytes, encoded without padding.
     *
     * @param  string  $bytes
     * @return string
     */
    public static function encode(#[\SensitiveParameter] string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * The bytes the value encodes, or `null` when it is not the canonical
     * unpadded base64url encoding of any.
     *
     * @param  string  $value
     * @return ?string
     */
    public static function decode(#[\SensitiveParameter] string $value): ?string
    {
        $bytes = base64_decode(strtr($value, '-_', '+/'), true);

        return is_string($bytes) && self::encode($bytes) === $value ? $bytes : null;
    }
}
