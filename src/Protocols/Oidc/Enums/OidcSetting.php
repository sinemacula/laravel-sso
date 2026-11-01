<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Enums;

use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;

/**
 * The settings of an OpenID Connect connection (SSO-2.4, SSO-7.1, SSO-7.3), by
 * the name each is stored, given, refused and reported under; the value is that
 * name. What each holds and how it is validated belongs to the OIDC settings;
 * which changes need fresh authentication, which may change what existing
 * subjects mean, and which is a secret, is fixed here, so every part of the
 * package classifies a change the same way.
 *
 * The callback URL is built by the endpoint resolver, never stored (SSO-5.5);
 * the `private_key_jwt` key pair is kept with the connection's keys (SSO-2.7).
 *
 * The names are stable once released: a value is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum OidcSetting: string
{
    // The issuer, which the ID token's `iss`, the discovery document and the
    // RFC 9207 `iss` parameter must equal exactly (SSO-2.8, SSO-7.1, SSO-7.4)
    case ISSUER = 'issuer';

    // The authorisation endpoint the browser is sent to
    case AUTHORIZATION_ENDPOINT = 'authorization_endpoint';

    // The token endpoint the code is exchanged at
    case TOKEN_ENDPOINT = 'token_endpoint';

    // The JWKS the ID token's signing keys are read from
    case JWKS_URI = 'jwks_uri';

    // The optional UserInfo endpoint
    case USERINFO_ENDPOINT = 'userinfo_endpoint';

    // Whether the provider returns the RFC 9207 `iss` parameter, which is then
    // required (SSO-7.1)
    case RETURNS_ISS = 'returns_iss';

    // The connection's client id at the identity provider
    case CLIENT_ID = 'client_id';

    // The client secret, for `client_secret_basic` and `client_secret_post`:
    // stored encrypted and never read back (SSO-2.5)
    case CLIENT_SECRET = 'client_secret';

    // How the client authenticates at the token endpoint:
    // `client_secret_basic`, `client_secret_post` or `private_key_jwt`
    case CLIENT_AUTHENTICATION = 'client_authentication';

    // The scopes requested, always including `openid`
    case SCOPES = 'scopes';

    // The ID token signature algorithms accepted, asymmetric only (SSO-7.3)
    case ID_TOKEN_ALGORITHMS = 'id_token_algorithms';

    // Extra authorisation parameters from the allow-list (`prompt`,
    // `acr_values`, `login_hint`, ...), never one the flow controls
    case EXTRA_PARAMETERS = 'extra_parameters';

    /**
     * The operation whose freshness a change to the setting needs, or `null`
     * when its change never widens or redirects access (SSO-2.12): what decides
     * whom the connection trusts, where it sends people or the code, what a
     * subject means, what a signature must be, and the client's credentials, is
     * trust.
     *
     * @return ?\SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation
     */
    public function freshness(): ?FreshnessOperation
    {
        return match ($this) {
            self::SCOPES, self::EXTRA_PARAMETERS => null,
            default                              => FreshnessOperation::CONNECTION_TRUST,
        };
    }

    /**
     * Whether a change to the setting may alter what existing subjects mean
     * (SSO-2.13).
     *
     * @return bool
     */
    public function altersSubject(): bool
    {
        return $this === self::ISSUER || $this === self::CLIENT_ID;
    }

    /**
     * Whether the setting is a secret, stored encrypted and masked on read
     * (SSO-2.5).
     *
     * @return bool
     */
    public function isSecret(): bool
    {
        return $this === self::CLIENT_SECRET;
    }

    /**
     * The names of the settings a change to which may alter what existing
     * subjects mean.
     *
     * @return list<string>
     */
    public static function subjectNames(): array
    {
        return array_values(array_map(
            static fn (self $setting): string => $setting->value,
            array_filter(self::cases(), static fn (self $setting): bool => $setting->altersSubject()),
        ));
    }

    /**
     * The names of the settings that are secrets.
     *
     * @return list<string>
     */
    public static function secretNames(): array
    {
        return array_values(array_map(
            static fn (self $setting): string => $setting->value,
            array_filter(self::cases(), static fn (self $setting): bool => $setting->isSecret()),
        ));
    }
}
