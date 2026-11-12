<?php

declare(strict_types = 1);

namespace Tests\Feature\Connections;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\AttributeMapping;
use SineMacula\Laravel\Sso\Connections\MappingLimits;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcSettings;
use SineMacula\Laravel\Sso\Protocols\Presets;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Settings;
use Tests\TestCase;

/**
 * Feature tests holding the shipped presets to the settings' rules.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Saml2Settings::class)]
#[CoversClass(OidcSettings::class)]
#[CoversClass(AttributeMapping::class)]
final class PresetSettingsTest extends TestCase
{
    /**
     * Every preset's settings and mapping are valid and hold no secret.
     *
     * @return void
     */
    public function testEveryPresetIsValid(): void
    {
        $protocols = $this->app?->make(ProtocolManager::class);
        $limits    = $this->app?->make(MappingLimits::class);

        self::assertInstanceOf(ProtocolManager::class, $protocols);
        self::assertInstanceOf(MappingLimits::class, $limits);
        self::assertSame(array_keys(Presets::shipped()), array_keys($protocols->presets()));

        foreach ($protocols->presets() as $name => $preset) {

            $settings = $protocols->protocol($preset->protocol)->settings($preset->settings);

            self::assertSame([], $settings->violations(), $name);
            self::assertSame([], array_intersect(array_keys($preset->settings), $settings::secretNames()), $name);
            self::assertSame([], AttributeMapping::fromArray($preset->protocol, $preset->attributeMapping, $limits)->violations(), $name);
            self::assertSame([], AttributeMapping::fromArray($preset->protocol, $preset->fillMapping(AttributeMapping::defaults($preset->protocol)), $limits)->violations(), $name);
            self::assertSame(
                [],
                AttributeMapping::fromArray($preset->protocol, array_replace(AttributeMapping::defaults($preset->protocol), $preset->attributeMapping), $limits)->violations(),
                $name,
            );
        }
    }

    /**
     * Google's preset is complete once the client id is given.
     *
     * @return void
     */
    public function testTheGooglePresetIsCompleteWithAClientId(): void
    {
        $google = Presets::shipped()['google'];

        self::assertFalse(OidcSettings::fromArray($google->settings)->isComplete());
        self::assertTrue(OidcSettings::fromArray($google->fill(['client_id' => 'client-123']))->isComplete());
    }
}
