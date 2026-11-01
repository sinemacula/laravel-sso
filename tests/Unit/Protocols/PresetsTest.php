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

    /**
     * Each OIDC preset fills in how its client authenticates at the token
     * endpoint, and the claims each attribute is read from.
     *
     * @return void
     */
    public function testEachOidcPresetFillsInItsClientAuthenticationAndMapping(): void
    {
        $presets = Presets::shipped();
        $mapping = ['email' => 'email', 'given_name' => 'given_name', 'family_name' => 'family_name', 'display_name' => 'name'];

        self::assertSame([
            'google'          => 'client_secret_basic',
            'microsoft_entra' => 'client_secret_basic',
            'okta'            => 'client_secret_basic',
            'auth0'           => 'client_secret_post',
        ], array_map(static fn ($preset): mixed => $preset->settings['client_authentication'] ?? null, array_diff_key($presets, ['microsoft_entra_saml' => true])));

        self::assertSame($mapping, $presets['google']->attributeMapping);
        self::assertSame($mapping, $presets['microsoft_entra']->attributeMapping);
        self::assertSame($mapping + ['groups' => 'groups'], $presets['okta']->attributeMapping);
        self::assertSame($mapping, $presets['auth0']->attributeMapping);
    }

    /**
     * Microsoft Entra ID's SAML preset fills in its binding, subject and
     * signing requirement, and the claim types its attributes are named by.
     *
     * @return void
     */
    public function testMicrosoftEntraSamlFillsInItsSettingsAndClaimTypes(): void
    {
        $preset = Presets::shipped()['microsoft_entra_saml'];

        self::assertSame([
            'sso_binding'            => 'http_redirect',
            'subject_source'         => 'name_id',
            'name_id_format'         => 'persistent',
            'want_assertions_signed' => true,
        ], $preset->settings);

        self::assertSame([
            'email'        => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
            'given_name'   => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
            'family_name'  => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
            'display_name' => 'http://schemas.microsoft.com/identity/claims/displayname',
            'groups'       => 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups',
        ], $preset->attributeMapping);
    }
}
