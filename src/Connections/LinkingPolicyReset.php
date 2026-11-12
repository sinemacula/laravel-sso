<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Clears a connection's linking policy when its issuer changes, since the
 * policy was a statement about the old issuer.
 *
 * The SAML attribute is kept: it says nothing about the issuer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LinkingPolicyReset
{
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
     * The columns that change, with the raised version; none when nothing does.
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

        return $reset === [] ? [] : [...$reset, 'linking_version' => $locked->linking_version + 1];
    }

    /**
     * The reported names of what the reset changes.
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
