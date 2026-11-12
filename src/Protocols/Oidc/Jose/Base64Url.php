<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose;

/**
 * Unpadded base64url (RFC 7515), decoded strictly so a value has exactly one
 * accepted spelling.
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
     * Encode the bytes without padding.
     *
     * @param  string  $bytes
     * @return string
     */
    public static function encode(#[\SensitiveParameter] string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * Decode the value, or return `null` when it is not canonical unpadded
     * base64url.
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
