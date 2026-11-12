<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

/**
 * The shipped presets. Each fills in only what every organisation on the
 * provider shares; tenant domains, issuers and client credentials are given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class Presets
{
    /** @var array<string, string> Standard OIDC claims by target attribute. */
    private const array OIDC_MAPPING = [
        'email'        => 'email',
        'given_name'   => 'given_name',
        'family_name'  => 'family_name',
        'display_name' => 'name',
    ];

    /** @var array<string, mixed> Settings every shipped OIDC preset fills in. */
    private const array OIDC_SETTINGS = [
        'scopes'              => ['openid', 'email', 'profile'],
        'id_token_algorithms' => ['RS256'],
    ];

    /** @var string Pattern of a Microsoft Entra ID tenant's OIDC issuer. */
    private const string ENTRA_ISSUERS = '#^https://(?:login\.microsoftonline\.com/[^/]+/v2\.0|sts\.windows\.net/[^/]+/)$#D';

    /** @var string Pattern of a Microsoft Entra ID tenant's SAML entity id. */
    private const string ENTRA_ENTITY_IDS = '#^https://sts\.windows\.net/[^/]+/$#D';

    /** @var string Namespace of the WS claim types Entra ID's SAML attributes use. */
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
