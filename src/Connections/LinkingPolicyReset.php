<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * What a change of a connection's issuer does to its linking policy (SSO-8.8,
 * SSO-2.13): the classification, the organisation and the acknowledgement were
 * an administrator's statement about one issuer, and never stand for another. A
 * change of a setting the protocol's `issuerNames()` lists, through
 * `ConnectionService::update()`, an import or `SubjectMigration`, therefore
 * turns linking off, clears them and raises `linking_version` in the same save,
 * so the administrator classifies the new issuer through
 * `LinkingPolicyService`. The organisation's claim and value go too, since a
 * later `issuer_class: shared` would otherwise silently reuse the old issuer's.
 * The SAML attribute stays: it names nothing about the issuer, and it needs the
 * acknowledgement given again regardless.
 *
 * A connection that holds no such statement, or a change of any other setting,
 * resets nothing. It holds nothing (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LinkingPolicyReset
{
    /** @var string The column that counts changes of the policy. */
    private const string VERSION = 'linking_version';

    /** @var array<string, bool|null> What each column of the statement is reset to. */
    private const array CLEARED = [
        'linking_enabled'            => false,
        'linking_issuer_class'       => null,
        'linking_organization_claim' => null,
        'linking_organization_value' => null,
        'linking_acknowledged_at'    => null,
    ];

    /** @var array<string, string> The name a change is reported by, by the column reset. */
    private const array NAMES = [
        'linking_enabled'            => 'linking.enabled',
        'linking_issuer_class'       => 'linking.issuer_class',
        'linking_organization_claim' => 'linking.organization_claim',
        'linking_organization_value' => 'linking.organization_value',
        'linking_acknowledged_at'    => 'linking.acknowledged',
    ];

    /**
     * The columns to write for the change to the locked connection: only those
     * that change, with the raised version; none when nothing does.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Contracts\ProtocolSettings  $settings
     * @param  list<string>  $changedSettings
     * @return array<string, bool|int|null>
     */
    public static function of(Connection $locked, ProtocolSettings $settings, array $changedSettings): array
    {
        if (array_intersect($changedSettings, $settings::issuerNames()) === []) {
            return [];
        }

        $reset = array_filter(self::CLEARED, static fn (?bool $cleared, string $column): bool => $locked->getAttribute($column) !== $cleared, ARRAY_FILTER_USE_BOTH);

        return $reset === [] ? [] : [...$reset, self::VERSION => $locked->linking_version + 1];
    }

    /**
     * The names, for the event and the result, of what the reset changes.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
     * @param  \SineMacula\Laravel\Sso\Contracts\ProtocolSettings  $settings
     * @param  list<string>  $changedSettings
     * @return list<string>
     */
    public static function changedNames(Connection $locked, ProtocolSettings $settings, array $changedSettings): array
    {
        return array_values(array_intersect_key(self::NAMES, self::of($locked, $settings, $changedSettings)));
    }
}
