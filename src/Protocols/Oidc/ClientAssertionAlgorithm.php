<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use SineMacula\Laravel\Sso\Keys\Enums\KeyType;

/**
 * Which algorithm signs a `private_key_jwt` client assertion (SSO-2.4, RFC
 * 7523): an RSA key signs with `PS256` by default or `RS256` when the
 * connection pins it, and a P-256 key with `ES256`, its default and its only
 * one. The connection's `client_assertion_algorithm` pins it, and is never
 * negotiated from a response or discovery, nor retried under another; it is
 * apart from the allow-list of `id_token_algorithms`, which judges what the
 * provider signs.
 *
 * The settings judge a value alone. Whether it fits the connection's keys is
 * judged here, by every path that can break the pair: a change of the setting
 * (`Connections\ConnectionService`), a key added (`Keys\KeyService`), whether
 * the connection is complete (`OidcDriver::isComplete()`) and its description
 * (`RelyingPartyDescription`).
 *
 * It holds nothing between calls (SSO-11.2).
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

    /** @var string RSA PKCS #1 v1.5 over SHA-256, an RSA key's alternative for a provider that accepts nothing else. */
    public const string RS256 = 'RS256';

    /** @var string ECDSA on P-256 over SHA-256, a P-256 key's default and only algorithm. */
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
     * Whether a key of the type can sign under the pinned algorithm; with none
     * pinned, it signs with its own default.
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
