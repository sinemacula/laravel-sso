<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;

/**
 * An OpenID Connect connection's settings, typed, for the driver and its
 * collaborators to read (SSO-2.4): every setting of `OidcSettings`, defaults
 * applied, through an accessor of its own. It is read from what the connection
 * holds at the moment it is built, which the driver does once per call, so
 * nothing is kept between calls (SSO-11.2).
 *
 * Only a complete connection is ever used (`OidcDriver::isComplete()`), so a
 * flow reads a valid issuer, endpoints and client id; a setting the connection
 * does not hold is `null` (or its default), and an accessor that needs one
 * throws a `LogicException`, the caller's mistake. It holds no secret: the
 * client secret is read from the connection's secrets and the `private_key_jwt`
 * key from its keys, each only for the call that sends it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OidcOptions
{
    /**
     * Constructor.
     *
     * @param  array<string, mixed>  $settings
     */
    private function __construct(

        /** Every setting, defaults applied, by name. */
        private array $settings,
    ) {}

    /**
     * The options of the connection as it holds them now.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return self
     */
    public static function of(SsoConnection $connection): self
    {
        return new self(OidcSettings::fromArray($connection->getSettings())->toArray());
    }

    /**
     * The issuer, exactly as configured.
     *
     * @return string
     *
     * @throws \LogicException
     */
    public function issuer(): string
    {
        return $this->required(OidcSetting::ISSUER);
    }

    /**
     * The authorisation endpoint.
     *
     * @return string
     *
     * @throws \LogicException
     */
    public function authorizationEndpoint(): string
    {
        return $this->required(OidcSetting::AUTHORIZATION_ENDPOINT);
    }

    /**
     * The token endpoint, exactly as configured: a client assertion's `aud`.
     *
     * @return string
     *
     * @throws \LogicException
     */
    public function tokenEndpoint(): string
    {
        return $this->required(OidcSetting::TOKEN_ENDPOINT);
    }

    /**
     * The JWKS URL.
     *
     * @return string
     *
     * @throws \LogicException
     */
    public function jwksUri(): string
    {
        return $this->required(OidcSetting::JWKS_URI);
    }

    /**
     * The UserInfo endpoint, or `null` when the connection names none.
     *
     * @return ?string
     */
    public function userInfoEndpoint(): ?string
    {
        $value = $this->settings[OidcSetting::USERINFO_ENDPOINT->value] ?? null;

        return is_string($value) ? $value : null;
    }

    /**
     * The connection's client id at the identity provider.
     *
     * @return string
     *
     * @throws \LogicException
     */
    public function clientId(): string
    {
        return $this->required(OidcSetting::CLIENT_ID);
    }

    /**
     * How the client authenticates at the token endpoint:
     * `client_secret_basic`, `client_secret_post` or `private_key_jwt`.
     *
     * @return string
     */
    public function clientAuthentication(): string
    {
        $method = $this->settings[OidcSetting::CLIENT_AUTHENTICATION->value] ?? null;

        return is_string($method) ? $method : '';
    }

    /**
     * Whether the connection says its provider returns the RFC 9207 `iss`.
     *
     * @return bool
     */
    public function returnsIss(): bool
    {
        return $this->settings[OidcSetting::RETURNS_ISS->value] === true;
    }

    /**
     * The scopes, in order, `openid` among them.
     *
     * @return list<string>
     */
    public function scopes(): array
    {
        return $this->strings(OidcSetting::SCOPES);
    }

    /**
     * The ID token algorithm allow-list.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList
     *
     * @throws \InvalidArgumentException
     */
    public function algorithms(): AlgorithmAllowList
    {
        return AlgorithmAllowList::of($this->strings(OidcSetting::ID_TOKEN_ALGORITHMS));
    }

    /**
     * The extra authorisation parameters, by name.
     *
     * @return array<string, string>
     */
    public function extraParameters(): array
    {
        /** @var array<string, string> */
        return (array) ($this->settings[OidcSetting::EXTRA_PARAMETERS->value] ?? []);
    }

    /**
     * The audiences an ID token may name beside the client id.
     *
     * @return list<string>
     */
    public function trustedAudiences(): array
    {
        return $this->strings(OidcSetting::TRUSTED_AUDIENCES);
    }

    /**
     * The `max_age` every authorisation request sends, in seconds, or `null`
     * when none is configured.
     *
     * @return ?int
     */
    public function maxAge(): ?int
    {
        $value = $this->settings[OidcSetting::MAX_AGE->value] ?? null;

        return is_int($value) ? $value : null;
    }

    /**
     * Whether UserInfo is fetched, and then mandatory.
     *
     * @return bool
     */
    public function fetchesUserInfo(): bool
    {
        return $this->settings[OidcSetting::FETCH_USERINFO->value] === true;
    }

    /**
     * Whether the discovery document and the JWKS refresh on a schedule.
     *
     * @return bool
     */
    public function refreshes(): bool
    {
        return $this->settings[OidcSetting::METADATA_REFRESH->value] === true;
    }

    /**
     * The setting as a string, which a complete connection holds.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting  $setting
     * @return string
     *
     * @throws \LogicException
     */
    private function required(OidcSetting $setting): string
    {
        $value = $this->settings[$setting->value] ?? null;

        if (!is_string($value)) {
            throw new \LogicException(sprintf('The connection has no [%s]; only a complete connection is used.', $setting->value));
        }

        return $value;
    }

    /**
     * The list setting's strings.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting  $setting
     * @return list<string>
     */
    private function strings(OidcSetting $setting): array
    {
        $value = $this->settings[$setting->value] ?? [];

        return is_array($value) ? array_values(array_filter($value, is_string(...))) : [];
    }
}
