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
 * Whether a SAML connection follows its metadata URL (SSO-2.8), which
 * everything about its refresh and its stale deadline reads from here.
 *
 * HTTPS proves only who served a file, so a metadata URL alone is never trust
 * in what it serves. A metadata signing anchor (a trusted
 * `KeyUse::METADATA_SIGNING` certificate) is, and `metadata_refresh` set `true`
 * is an administrator delegating that trust to the URL and its TLS, a trust
 * change like any other.
 *
 * - The schedule refreshes a connection with a valid `metadata_url` when
 *   `metadata_refresh` is `true`, or when it is unset and the connection has an
 *   anchor (`refreshes()`). Adding the anchor turns that default on and
 *   removing it turns it off, with no other change. `false` is always off.
 * - What was fetched holds a stale deadline when the connection has a valid
 *   `metadata_url` and either `metadata_refresh` is `true` or it has an anchor,
 *   so `false` on an anchored connection keeps what a validated fetch counts for
 *   (`holdsDeadline()`). Any other SAML connection behaves like one whose
 *   certificates were entered by hand: nothing it holds expires, whatever was
 *   stamped earlier, and nothing recovering it is needed.
 * - A connection that comes to hold a deadline starts with none running: the
 *   URL, the switch or the first anchor that brings it in clears what was
 *   stamped while it held none, and makes its first refresh due
 *   (`resetForSettings()`, `resetForAnchor()`), so an old stamp never expires
 *   it the moment it opts in.
 *
 * It reads the anchors on the write connection (SSO-11.3), only where the
 * answer depends on them, and holds nothing between calls (SSO-11.2).
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
     * Whether the schedule refreshes the SAML connection, given whether it has
     * an anchor, or reading that when it matters and is not given.
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
     * Which of the connections have an anchor, by id, reading the anchors once
     * and only for those whose refresh depends on it: a due listing asks this
     * of every connection it reads, on every run.
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

        return $ids === [] ? [] : array_fill_keys(self::anchors()->whereIn('connection_id', $ids)->distinct()->pluck('connection_id')->all(), true);
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
     * What an update changing the settings named, to the stored settings given,
     * must also write to the locked connection: nothing, unless it brings a
     * SAML connection to hold a deadline it did not hold before.
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
     * What trusting an anchor must also write to the locked connection, asked
     * before it is stored: nothing, unless the anchor is its first and brings
     * it to hold a deadline it did not hold before.
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
