<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc\Enums;

use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;

/**
 * The settings of an OpenID Connect connection and how a change to each is
 * classified. Values are stable once released and never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum OidcSetting: string
{
    // The issuer every `iss` and the discovery document must equal exactly
    case ISSUER = 'issuer';

    // The authorisation endpoint the browser is sent to
    case AUTHORIZATION_ENDPOINT = 'authorization_endpoint';

    // The token endpoint the code is exchanged at
    case TOKEN_ENDPOINT = 'token_endpoint';

    // The JWKS the ID token's signing keys are read from
    case JWKS_URI = 'jwks_uri';

    // The optional UserInfo endpoint
    case USERINFO_ENDPOINT = 'userinfo_endpoint';

    // Whether the provider returns the RFC 9207 `iss`, which is then required
    case RETURNS_ISS = 'returns_iss';

    // The connection's client id at the identity provider
    case CLIENT_ID = 'client_id';

    // The client secret, stored encrypted and never read back
    case CLIENT_SECRET = 'client_secret';

    // How the client authenticates at the token endpoint
    case CLIENT_AUTHENTICATION = 'client_authentication';

    // The pinned `private_key_jwt` signing algorithm, apart from
    // `id_token_algorithms`
    case CLIENT_ASSERTION_ALGORITHM = 'client_assertion_algorithm';

    // The scopes requested, always including `openid`
    case SCOPES = 'scopes';

    // The ID token signature algorithms accepted, asymmetric only
    case ID_TOKEN_ALGORITHMS = 'id_token_algorithms';

    // Extra allow-listed authorisation parameters, never one the flow controls
    case EXTRA_PARAMETERS = 'extra_parameters';

    // The audiences an ID token may name beside the client id
    case TRUSTED_AUDIENCES = 'trusted_audiences';

    // The `max_age` sent with every authorisation request, in seconds
    case MAX_AGE = 'max_age';

    // Whether UserInfo is called, which is then mandatory and fails closed
    case FETCH_USERINFO = 'fetch_userinfo';

    // Whether the discovery document and the JWKS are refreshed on a schedule
    case METADATA_REFRESH = 'metadata_refresh';

    /**
     * The operation whose freshness a change needs, or `null` when the change
     * never widens or redirects access.
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
     * Whether a change may alter what existing subjects mean.
     *
     * @return bool
     */
    public function altersSubject(): bool
    {
        return $this === self::ISSUER || $this === self::CLIENT_ID;
    }

    /**
     * Whether the setting is a secret, stored encrypted and masked on read.
     *
     * @return bool
     */
    public function isSecret(): bool
    {
        return $this === self::CLIENT_SECRET;
    }

    /**
     * The names of the settings that may alter what existing subjects mean.
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
