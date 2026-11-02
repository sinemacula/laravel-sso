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
 * `client_assertion` keys fit each other (SSO-2.4, RFC 7523), which is refused
 * wherever either changes: a change of the setting asks whether its keys fit it
 * (`Connections\ConnectionService`), and a key added asks whether it fits the
 * setting (`KeyService`).
 *
 * A change holds the connection's lock when it asks, so `publishedFit()` reads
 * the current and next keys with a locking read, which answers the latest
 * committed rows rather than an older snapshot of the caller's transaction; a
 * retiring key signs nothing, so it does not count.
 *
 * It holds nothing between calls (SSO-11.2).
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
     * Whether a key of the use and type may be added to the connection as it
     * holds its settings: a client assertion key must fit its pinned algorithm.
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
     * The problem with the settings' pinned algorithm, when a change of it
     * names one the package signs with but the locked connection's current or
     * next key cannot sign under: `unsupported`, read under its lock.
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
     * Whether the locked connection's current and next client assertion keys
     * can all sign under the pinned algorithm given, read with a locking read.
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
