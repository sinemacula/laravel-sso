<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys;

use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\Oidc\ClientAssertionAlgorithm;
use SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings;

/**
 * Whether a connection's `client_assertion_algorithm` and its
 * `client_assertion` keys fit each other.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ClientAssertionKeys
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether a key of the use and type fits the connection's pinned algorithm.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyType  $type
     * @return bool
     */
    public static function fits(Connection $connection, KeyUse $use, KeyType $type): bool
    {
        return $use !== KeyUse::CLIENT_ASSERTION || ClientAssertionAlgorithm::fits(self::pinnedBy($connection->settings), $type);
    }

    /**
     * An `unsupported` violation when a change pins a known algorithm the
     * locked connection's current or next key cannot sign under.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  array<string, mixed>  $stored
     * @param  list<string>  $changedSettings
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    public static function changeViolations(Connection $locked, array $stored, array $changedSettings): array
    {
        $name   = OidcSetting::CLIENT_ASSERTION_ALGORITHM->value;
        $pinned = self::pinnedBy($stored);
        $known  = $pinned === null || in_array($pinned, OidcSettings::CLIENT_ASSERTION_ALGORITHMS, true);

        if (!$known || !in_array($name, $changedSettings, true) || self::publishedFit($locked, $pinned)) {
            return [];
        }

        return [new SettingViolation($name, ViolationCode::UNSUPPORTED)];
    }

    /**
     * Whether the current and next client assertion keys can all sign under the
     * algorithm; read locked, so it sees rows newer than the caller's snapshot.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  ?string  $pinned
     * @return bool
     */
    private static function publishedFit(Connection $locked, ?string $pinned): bool
    {
        $types = ConnectionKey::query()->useWritePdo()
            ->where('connection_id', $locked->id)
            ->where('use', KeyUse::CLIENT_ASSERTION->value)
            ->whereIn('state', [KeyState::CURRENT->value, KeyState::NEXT->value])
            ->lockForUpdate()
            ->get()
            ->map(static fn (ConnectionKey $key): KeyType => $key->key_type)
            ->all();

        return array_filter($types, static fn (KeyType $type): bool => ClientAssertionAlgorithm::fits($pinned, $type)) === $types;
    }

    /**
     * The algorithm the settings pin, or `null` when they pin none.
     *
     * @param  array<string, mixed>  $settings
     * @return ?string
     */
    private static function pinnedBy(array $settings): ?string
    {
        $pinned = $settings[OidcSetting::CLIENT_ASSERTION_ALGORITHM->value] ?? null;

        return is_string($pinned) ? $pinned : null;
    }
}
