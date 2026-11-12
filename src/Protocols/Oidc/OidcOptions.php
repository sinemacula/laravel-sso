<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;

/**
 * An OpenID Connect connection's settings, typed and with defaults applied,
 * built once per driver call. It holds no secret.
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
     * Read the connection's current options.
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
     * The token endpoint exactly as configured, a client assertion's `aud`.
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
     * How the client authenticates at the token endpoint.
     *
     * @return string
     */
    public function clientAuthentication(): string
    {
        $method = $this->settings[OidcSetting::CLIENT_AUTHENTICATION->value] ?? null;

        return is_string($method) ? $method : '';
    }

    /**
     * The pinned client assertion algorithm, or `null` for the key's default.
     *
     * @return ?string
     */
    public function clientAssertionAlgorithm(): ?string
    {
        $algorithm = $this->settings[OidcSetting::CLIENT_ASSERTION_ALGORITHM->value] ?? null;

        return is_string($algorithm) ? $algorithm : null;
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
     * The `max_age` sent with every authorisation request, in seconds.
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
     * A string setting every complete connection holds.
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
