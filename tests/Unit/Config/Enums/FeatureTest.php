<?php

declare(strict_types = 1);

namespace Tests\Unit\Config\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Config\Enums\Feature;

/**
 * Unit tests for the feature switches.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Feature::class)]
final class FeatureTest extends TestCase
{
    /**
     * Every opt-in feature has a switch under `sso.features`.
     *
     * @return void
     */
    public function testEveryOptInFeatureHasASwitch(): void
    {
        self::assertSame(
            ['saml2', 'oidc', 'discovery', 'enforcement', 'encrypted_assertions', 'metadata_refresh', 'idp_initiated', 'domain_linking'],
            array_column(Feature::cases(), 'value'),
        );

        self::assertSame('sso.features.domain_linking', Feature::DOMAIN_LINKING->key());
    }

    /**
     * SAML-only features need `saml2`; the rest need either protocol.
     *
     * @return void
     */
    public function testEachFeatureNeedsItsProtocols(): void
    {
        $needs = [];

        foreach (Feature::cases() as $feature) {
            $needs[$feature->value] = array_column($feature->needs(), 'value');
        }

        self::assertSame([
            'saml2'                => [],
            'oidc'                 => [],
            'discovery'            => ['saml2', 'oidc'],
            'enforcement'          => ['saml2', 'oidc'],
            'encrypted_assertions' => ['saml2'],
            'metadata_refresh'     => [],
            'idp_initiated'        => ['saml2'],
            'domain_linking'       => ['saml2', 'oidc'],
        ], $needs);
    }

    /**
     * Only the scheduled refresh is on when its switch is not set.
     *
     * @return void
     */
    public function testOnlyTheScheduledRefreshIsOnByDefault(): void
    {
        $on = array_filter(Feature::cases(), static fn (Feature $feature): bool => $feature->isOnByDefault());

        self::assertSame([Feature::METADATA_REFRESH], array_values($on));
    }

    /**
     * Only `saml2` and `oidc` are protocols.
     *
     * @return void
     */
    public function testOnlyTheProtocolsAreProtocols(): void
    {
        $protocols = array_filter(Feature::cases(), static fn (Feature $feature): bool => $feature->isProtocol());

        self::assertSame([Feature::SAML2, Feature::OIDC], array_values($protocols));
    }
}
