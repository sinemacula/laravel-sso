<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata;

use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Sso\Connections\SettingRules;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver;

/**
 * Whether a SAML connection follows its metadata URL, for its refresh and its
 * stale deadline.
 *
 * HTTPS proves only who served a file, so only an anchor or an explicit
 * `metadata_refresh` of `true` makes the URL trusted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SamlRefreshRule
{
    /** @var array<string, null> What a connection that comes to hold a deadline starts from. */
    private const array NOTHING_FETCHED = ['metadata_fetched_at' => null, 'metadata_valid_until' => null, 'metadata_refresh_at' => null];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether the settings name a metadata URL the package may fetch.
     *
     * @param  array<string, mixed>  $settings
     * @return bool
     */
    public static function hasUrl(array $settings): bool
    {
        return SettingRules::url($settings[Saml2Setting::METADATA_URL->value] ?? null) === null;
    }

    /**
     * Whether the schedule refreshes the SAML connection; `$anchored` is read
     * when it matters and is not given.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?bool  $anchored
     * @return bool
     */
    public static function refreshes(Connection $connection, ?bool $anchored = null): bool
    {
        if (!self::hasUrl($connection->settings)) {
            return false;
        }

        return (self::switchOf($connection->settings) ?? $anchored ?? self::isAnchored($connection->id)) === true;
    }

    /**
     * Which of the connections have an anchor, by id, in one read and only for
     * those whose refresh depends on it, since every run asks this.
     *
     * @param  list<\SineMacula\Laravel\Sso\Models\Connection>  $connections
     * @return array<string, true>
     */
    public static function anchoredAmong(array $connections): array
    {
        $ids = [];

        foreach ($connections as $connection) {

            if (self::switchOf($connection->settings) !== null) {
                continue;
            }

            $ids[] = $connection->id;
        }

        if ($ids === []) {
            return [];
        }

        $anchored = self::anchors()->whereIn('connection_id', $ids)->distinct()->pluck('connection_id')->all();

        return array_fill_keys(array_filter($anchored, is_string(...)), true);
    }

    /**
     * Whether what was fetched for the connection holds a stale deadline: every
     * protocol's does, but for a SAML connection that has not opted in.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return bool
     */
    public static function holdsDeadline(Connection $connection): bool
    {
        if ($connection->protocol !== Saml2Driver::NAME) {
            return true;
        }

        if (!self::hasUrl($connection->settings)) {
            return false;
        }

        return self::switchOf($connection->settings) === true || self::isAnchored($connection->id);
    }

    /**
     * What an update must also write to the locked connection when it brings it
     * to hold a deadline, so an old stamp never expires it on opting in.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  list<string>  $changedSettings
     * @param  array<string, mixed>  $stored
     * @return array<string, null>
     */
    public static function resetForSettings(Connection $locked, array $changedSettings, array $stored): array
    {
        $moved = array_intersect([Saml2Setting::METADATA_URL->value, Saml2Setting::METADATA_REFRESH->value], $changedSettings) !== [];

        if ($locked->protocol !== Saml2Driver::NAME || !$moved) {
            return [];
        }

        $anchored = self::isAnchored($locked->id);

        return self::holds($stored, $anchored) && !self::holds($locked->settings, $anchored) ? self::NOTHING_FETCHED : [];
    }

    /**
     * What trusting an anchor must also write when it is the first and brings
     * the connection to hold a deadline; ask before the anchor is stored.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @return array<string, null>
     */
    public static function resetForAnchor(Connection $locked): array
    {
        if (!self::hasUrl($locked->settings) || self::switchOf($locked->settings) === true) {
            return [];
        }

        return self::isAnchored($locked->id) ? [] : self::NOTHING_FETCHED;
    }

    /**
     * Whether the settings, with or without an anchor, hold a deadline.
     *
     * @param  array<string, mixed>  $settings
     * @param  bool  $anchored
     * @return bool
     */
    private static function holds(array $settings, bool $anchored): bool
    {
        return self::hasUrl($settings) && ($anchored || self::switchOf($settings) === true);
    }

    /**
     * The connection's `metadata_refresh`, `null` while it is unset.
     *
     * @param  array<string, mixed>  $settings
     * @return mixed
     */
    private static function switchOf(array $settings): mixed
    {
        return $settings[Saml2Setting::METADATA_REFRESH->value] ?? null;
    }

    /**
     * Whether the connection has a metadata signing anchor.
     *
     * @param  string  $connectionId
     * @return bool
     */
    private static function isAnchored(string $connectionId): bool
    {
        return self::anchors()->where('connection_id', $connectionId)->exists();
    }

    /**
     * A query of the metadata signing anchors, on the write connection.
     *
     * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Sso\Models\ConnectionKey>
     */
    private static function anchors(): Builder
    {
        return ConnectionKey::query()->useWritePdo()->where('use', KeyUse::METADATA_SIGNING->value);
    }
}
