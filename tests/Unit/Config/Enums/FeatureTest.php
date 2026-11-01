<?php

declare(strict_types = 1);

namespace Tests\Unit\Config\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Config\Enums\Feature;

/**
 * Unit tests for the feature switches: their keys, which are protocols, and
 * which protocols every other feature needs.
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
     * Every feature of FEATURES' "Every feature is opt-in" has a switch, under
     * `sso.features`.
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
     * The protocols need nothing; the SAML-only features need `saml2`; every
     * other feature needs either protocol.
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
            'metadata_refresh'     => ['saml2', 'oidc'],
            'idp_initiated'        => ['saml2'],
            'domain_linking'       => ['saml2', 'oidc'],
        ], $needs);
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
