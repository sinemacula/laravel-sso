<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting;
use SineMacula\Laravel\Sso\Protocols\Presets;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;

/**
 * Unit tests for the presets the package ships: which there are, that each is
 * keyed by its name, fills in only settings its protocol has and never a
 * secret, always requests `openid`, and names the organisation claim of a
 * shared issuer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Presets::class)]
final class PresetsTest extends TestCase
{
    /**
     * The shipped presets, each keyed by its own name.
     *
     * @return void
     */
    public function testTheShippedPresetsAreKeyedByName(): void
    {
        $presets = Presets::shipped();

        self::assertSame(['google', 'microsoft_entra', 'okta', 'auth0', 'microsoft_entra_saml'], array_keys($presets));

        foreach ($presets as $name => $preset) {
            self::assertSame($name, $preset->name);
        }
    }

    /**
     * Each preset fills in only settings its protocol has, never a secret, and
     * an OIDC preset always requests `openid`.
     *
     * @return void
     */
    public function testEachFillsInOnlyItsProtocolsSettingsAndNoSecret(): void
    {
        foreach (Presets::shipped() as $preset) {

            $names = $preset->protocol === 'oidc'
                ? array_column(OidcSetting::cases(), 'value')
                : array_column(Saml2Setting::cases(), 'value');

            self::assertSame([], array_diff(array_keys($preset->settings), $names), "{$preset->name} fills in a setting its protocol does not have.");

            if ($preset->protocol !== 'oidc') {
                continue;
            }

            self::assertSame([], array_intersect(array_keys($preset->settings), OidcSetting::secretNames()), "{$preset->name} fills in a secret.");
            self::assertIsArray($preset->settings['scopes']);
            self::assertContains('openid', $preset->settings['scopes']);
        }
    }

    /**
     * The presets of shared issuers name their organisation claim; the others
     * name none.
     *
     * @return void
     */
    public function testSharedIssuersNameTheirOrganizationClaim(): void
    {
        $claims = array_map(static fn ($preset): ?string => $preset->organizationClaim, Presets::shipped());

        self::assertSame([
            'google'               => 'hd',
            'microsoft_entra'      => 'tid',
            'okta'                 => null,
            'auth0'                => null,
            'microsoft_entra_saml' => 'http://schemas.microsoft.com/identity/claims/tenantid',
        ], $claims);
    }

    /**
     * Google's preset fills in its fixed issuer and endpoints, all `https`.
     *
     * @return void
     */
    public function testGoogleFillsInItsIssuerAndEndpoints(): void
    {
        $google = Presets::shipped()['google'];

        self::assertSame('https://accounts.google.com', $google->settings['issuer']);

        foreach (['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint'] as $endpoint) {
            self::assertIsString($google->settings[$endpoint]);
            self::assertStringStartsWith('https://', $google->settings[$endpoint]);
        }
    }
}
