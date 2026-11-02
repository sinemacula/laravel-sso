<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

/**
 * The presets the package ships (SSO-2.2): settings for well-known identity
 * providers, as data. Each fills in only what is the same for every
 * organisation using the provider; what is particular to one (Okta's and
 * Auth0's domains, a Microsoft Entra tenant's issuer, the client id and secret)
 * the administrator gives, or imports from the issuer's discovery document.
 *
 * - `google`: Google Workspace over OIDC. One issuer for every organisation,
 *   told apart by the `hd` claim.
 * - `microsoft_entra`: Microsoft Entra ID over OIDC. Its issuer names the
 *   directory, told apart by the `tid` claim.
 * - `okta`, `auth0`: Okta and Auth0 over OIDC.
 * - `microsoft_entra_saml`: Microsoft Entra ID over SAML 2.0, with its claim
 *   names; told apart by its tenant id claim.
 *
 * An application adds its own through `ProtocolManager::registerPreset()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class Presets
{
    /** @var array<string, string> The standard OIDC claims each target attribute is read from. */
    private const array OIDC_MAPPING = [
        'email'        => 'email',
        'given_name'   => 'given_name',
        'family_name'  => 'family_name',
        'display_name' => 'name',
    ];

    /** @var array<string, mixed> The OIDC settings every shipped OIDC preset fills in. */
    private const array OIDC_SETTINGS = [
        'scopes'              => ['openid', 'email', 'profile'],
        'id_token_algorithms' => ['RS256'],
    ];

    /** @var string What each issuer of a Microsoft Entra ID directory over OIDC looks like. */
    private const string ENTRA_ISSUERS = '#^https://(?:login\.microsoftonline\.com/[^/]+/v2\.0|sts\.windows\.net/[^/]+/)$#D';

    /** @var string What each entity id of a Microsoft Entra ID directory over SAML looks like. */
    private const string ENTRA_ENTITY_IDS = '#^https://sts\.windows\.net/[^/]+/$#D';

    /** @var string The namespace of the claim types Microsoft Entra ID's SAML attributes are named by. */
    private const string WS_CLAIMS = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/';

    /** @var string The namespace of Microsoft's own SAML claim types. */
    private const string MS_CLAIMS = 'http://schemas.microsoft.com/identity/claims/';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The shipped presets, by name.
     *
     * @return array<string, \SineMacula\Laravel\Sso\Protocols\Preset>
     */
    public static function shipped(): array
    {
        $presets = [
            self::google(),
            new Preset('microsoft_entra', 'oidc', ['client_authentication' => 'client_secret_basic'] + self::OIDC_SETTINGS, self::OIDC_MAPPING, 'tid', self::ENTRA_ISSUERS),
            new Preset('okta', 'oidc', ['client_authentication' => 'client_secret_basic'] + self::OIDC_SETTINGS, self::OIDC_MAPPING + ['groups' => 'groups']),
            new Preset('auth0', 'oidc', ['client_authentication' => 'client_secret_post'] + self::OIDC_SETTINGS, self::OIDC_MAPPING),
            self::microsoftEntraSaml(),
        ];

        $named = [];

        foreach ($presets as $preset) {
            $named[$preset->name] = $preset;
        }

        return $named;
    }

    /**
     * Google Workspace over OIDC.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Preset
     */
    private static function google(): Preset
    {
        return new Preset('google', 'oidc', [
            'issuer'                 => 'https://accounts.google.com',
            'authorization_endpoint' => 'https://accounts.google.com/o/oauth2/v2/auth',
            'token_endpoint'         => 'https://oauth2.googleapis.com/token',
            'jwks_uri'               => 'https://www.googleapis.com/oauth2/v3/certs',
            'userinfo_endpoint'      => 'https://openidconnect.googleapis.com/v1/userinfo',
            'client_authentication'  => 'client_secret_basic',
        ] + self::OIDC_SETTINGS, self::OIDC_MAPPING, 'hd');
    }

    /**
     * Microsoft Entra ID over SAML 2.0.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Preset
     */
    private static function microsoftEntraSaml(): Preset
    {
        return new Preset('microsoft_entra_saml', 'saml2', [
            'sso_binding'            => 'http_redirect',
            'subject_source'         => 'name_id',
            'name_id_format'         => 'persistent',
            'want_assertions_signed' => true,
        ], [
            'email'        => self::WS_CLAIMS . 'emailaddress',
            'given_name'   => self::WS_CLAIMS . 'givenname',
            'family_name'  => self::WS_CLAIMS . 'surname',
            'display_name' => self::MS_CLAIMS . 'displayname',
            'groups'       => 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups',
        ], self::MS_CLAIMS . 'tenantid', self::ENTRA_ENTITY_IDS);
    }
}
