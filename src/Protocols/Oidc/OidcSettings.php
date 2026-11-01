<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\SettingRules;
use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting;

/**
 * The settings of an OpenID Connect connection (SSO-2.4, SSO-7.1, SSO-7.3),
 * named by `Enums\OidcSetting`, which also classifies a change to each.
 *
 * - `issuer`: an `https` URL with a host and no query, userinfo or fragment, of
 *   at most 2048 bytes, kept exactly as given: the ID token's `iss` must equal
 *   it, so it is never normalised (SSO-2.8).
 * - `authorization_endpoint`, `token_endpoint`, `jwks_uri` and the optional
 *   `userinfo_endpoint`: `https` URLs with a host and no userinfo or fragment,
 *   of at most 2048 bytes.
 * - `returns_iss`: whether the provider returns the RFC 9207 `iss` parameter
 *   (off by default).
 * - `client_id`: at most 255 bytes; `client_authentication`:
 *   `client_secret_basic` (the default), `client_secret_post` or
 *   `private_key_jwt`.
 * - `scopes`: up to twenty RFC 6749 scope tokens, always including `openid` (by
 *   default `openid`, `email` and `profile`).
 * - `id_token_algorithms`: asymmetric signature algorithms only (`RS256` by
 *   default), never `none` or an HMAC (SSO-7.3).
 * - `extra_parameters`: up to ten authorisation parameters from the allow-list
 *   (`prompt`, `acr_values`, `login_hint`, `ui_locales`, `claims_locales`,
 *   `display`, `domain_hint`, `hd`), each a string of at most 512 bytes. A
 *   parameter the flow controls is `reserved`, whatever its case, so none can
 *   ever be set or overridden (SSO-2.4).
 *
 * The client secret is a secret: the management helpers take it out of what is
 * given before the settings see it, so a `client_secret` among the settings is
 * `reserved`. A missing setting is not a violation, so a connection may be
 * saved before it is complete; `isComplete()` says when it is. What is stored
 * holds every setting given or defaulted, defaults applied.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class OidcSettings implements ProtocolSettings
{
    /** @var list<string> How the client may authenticate at the token endpoint. */
    public const array CLIENT_AUTHENTICATIONS = ['client_secret_basic', 'client_secret_post', 'private_key_jwt'];

    /** @var list<string> The ID token signature algorithms accepted: asymmetric only (SSO-7.3). */
    public const array ID_TOKEN_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512'];

    /** @var list<string> The extra authorisation parameters that may be set. */
    public const array EXTRA_PARAMETERS = ['prompt', 'acr_values', 'login_hint', 'ui_locales', 'claims_locales', 'display', 'domain_hint', 'hd'];

    /** @var list<string> The authorisation parameters the flow controls, in lower case; an extra parameter never sets one (SSO-2.4). */
    public const array RESERVED_PARAMETERS = [
        'response_type',
        'response_mode',
        'client_id',
        'redirect_uri',
        'scope',
        'state',
        'nonce',
        'code_challenge',
        'code_challenge_method',
        'request',
        'request_uri',
    ];

    /** @var int The longest client id, in bytes. */
    public const int MAX_CLIENT_ID_LENGTH = 255;

    /** @var int The most scopes that may be requested. */
    public const int MAX_SCOPES = 20;

    /** @var int The most extra parameters that may be set. */
    public const int MAX_EXTRA_PARAMETERS = 10;

    /** @var int The longest extra parameter value, in bytes. */
    public const int MAX_PARAMETER_LENGTH = 512;

    /** @var string The scope every request carries. */
    private const string OPENID = 'openid';

    /** @var string An RFC 6749 scope token: 1 to 255 of `%x21 / %x23-5B / %x5D-7E`. */
    private const string SCOPE_TOKEN = '/^[\x21\x23-\x5B\x5D-\x7E]+$/D';

    /** @var int The longest scope token, in bytes. */
    private const int MAX_SCOPE_LENGTH = 255;

    /** @var array<string, mixed> The value of each setting that has a default, by name. */
    private const array DEFAULTS = [
        'returns_iss'           => false,
        'client_authentication' => 'client_secret_basic',
        'scopes'                => ['openid', 'email', 'profile'],
        'id_token_algorithms'   => ['RS256'],
    ];

    /**
     * Constructor.
     *
     * @param  array<array-key, mixed>  $values
     */
    private function __construct(

        /** The settings given, by name, with no `null` among them. */
        private array $values,
    ) {}

    /**
     * The settings the values give, whatever their shape; a `null` value is a
     * setting not given.
     *
     * @param  array<array-key, mixed>  $values
     * @return static
     */
    #[\Override]
    public static function fromArray(array $values): static
    {
        $given = [];

        foreach ($values as $name => $value) {

            if ($value === null) {
                continue;
            }

            $given[$name] = $value;
        }

        return new self($given);
    }

    /**
     * The client secret.
     *
     * @return list<string>
     */
    #[\Override]
    public static function secretNames(): array
    {
        return OidcSetting::secretNames();
    }

    /**
     * The settings a change to which may alter what existing subjects mean.
     *
     * @return list<string>
     */
    #[\Override]
    public static function subjectNames(): array
    {
        return OidcSetting::subjectNames();
    }

    /**
     * The operation whose freshness a change to the setting needs, as
     * `OidcSetting` classifies it; `null` for a name it does not have.
     *
     * @param  string  $name
     * @return ?\SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation
     */
    #[\Override]
    public static function freshnessFor(string $name): ?FreshnessOperation
    {
        return OidcSetting::tryFrom($name)?->freshness();
    }

    /**
     * Every setting given or with a default, defaults applied, in the order
     * `OidcSetting` names them; never a secret.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function toArray(): array
    {
        $values = [];

        foreach (OidcSetting::cases() as $setting) {

            $name = $setting->value;

            if ($setting->isSecret()) {
                continue;
            }

            if (array_key_exists($name, $this->values)) {
                $values[$name] = $this->values[$name];
            } elseif (array_key_exists($name, self::DEFAULTS)) {
                $values[$name] = self::DEFAULTS[$name];
            }
        }

        return $values;
    }

    /**
     * Every problem with the settings, in the order `OidcSetting` names them,
     * then each name it does not have, as `unknown`.
     *
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    #[\Override]
    public function violations(): array
    {
        $violations = [];

        foreach (OidcSetting::cases() as $setting) {

            if (!array_key_exists($setting->value, $this->values)) {
                continue;
            }

            array_push($violations, ...self::check($setting, $this->values[$setting->value]));
        }

        foreach (array_keys($this->values) as $name) {

            if (OidcSetting::tryFrom((string) $name) !== null) {
                continue;
            }

            array_push($violations, ...SettingRules::at(SettingRules::path(null, $name), ViolationCode::UNKNOWN));
        }

        return $violations;
    }

    /**
     * Whether the settings are valid, and name the issuer, the authorisation,
     * token and JWKS endpoints, and the client id.
     *
     * @return bool
     */
    #[\Override]
    public function isComplete(): bool
    {
        $required = [OidcSetting::ISSUER, OidcSetting::AUTHORIZATION_ENDPOINT, OidcSetting::TOKEN_ENDPOINT, OidcSetting::JWKS_URI, OidcSetting::CLIENT_ID];

        foreach ($required as $setting) {
            if (!array_key_exists($setting->value, $this->values)) {
                return false;
            }
        }

        return $this->violations() === [];
    }

    /**
     * The problems with one setting given.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting  $setting
     * @param  mixed  $value
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    private static function check(OidcSetting $setting, mixed $value): array
    {
        $name = $setting->value;

        return match ($setting) {
            OidcSetting::ISSUER                => SettingRules::at($name, SettingRules::url($value, false)),
            OidcSetting::RETURNS_ISS           => SettingRules::at($name, SettingRules::boolean($value)),
            OidcSetting::CLIENT_ID             => SettingRules::at($name, SettingRules::text($value, self::MAX_CLIENT_ID_LENGTH)),
            OidcSetting::CLIENT_SECRET         => SettingRules::at($name, ViolationCode::RESERVED),
            OidcSetting::CLIENT_AUTHENTICATION => SettingRules::at($name, SettingRules::choice($value, self::CLIENT_AUTHENTICATIONS)),
            OidcSetting::SCOPES                => self::scopes($name, $value),
            OidcSetting::ID_TOKEN_ALGORITHMS   => SettingRules::allowedList($name, $value, self::ID_TOKEN_ALGORITHMS),
            OidcSetting::EXTRA_PARAMETERS      => self::extraParameters($name, $value),
            default                            => SettingRules::at($name, SettingRules::url($value)),
        };
    }

    /**
     * The scopes: a list of at most twenty distinct scope tokens, including
     * `openid`.
     *
     * @param  string  $name
     * @param  mixed  $value
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    private static function scopes(string $name, mixed $value): array
    {
        $code = SettingRules::list($value);

        if ($code !== null || !is_array($value)) {
            return SettingRules::at($name, $code ?? ViolationCode::INVALID_TYPE);
        }

        if (count($value) > self::MAX_SCOPES) {
            return SettingRules::at($name, ViolationCode::TOO_MANY);
        }

        $violations = [];
        $seen       = [];

        foreach ($value as $index => $scope) {

            $code = self::scope($scope) ?? (in_array($scope, $seen, true) ? ViolationCode::DUPLICATE : null);

            if ($code === null) {
                $seen[] = $scope;
            }

            array_push($violations, ...SettingRules::at($name . '.' . $index, $code));
        }

        if (!in_array(self::OPENID, $value, true)) {
            array_push($violations, ...SettingRules::at($name, ViolationCode::OPENID_SCOPE_REQUIRED));
        }

        return $violations;
    }

    /**
     * One scope token.
     *
     * @param  mixed  $scope
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    private static function scope(mixed $scope): ?ViolationCode
    {
        $code = SettingRules::text($scope, self::MAX_SCOPE_LENGTH, false);

        if ($code !== null || !is_string($scope)) {
            return $code;
        }

        return preg_match(self::SCOPE_TOKEN, $scope) === 1 ? null : ViolationCode::INVALID_FORMAT;
    }

    /**
     * The extra parameters: a map of at most ten names from the allow-list to
     * strings of at most 512 bytes; a name the flow controls, in any case, is
     * `reserved`.
     *
     * @param  string  $name
     * @param  mixed  $value
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    private static function extraParameters(string $name, mixed $value): array
    {
        if (!is_array($value)) {
            return SettingRules::at($name, ViolationCode::INVALID_TYPE);
        }

        if (count($value) > self::MAX_EXTRA_PARAMETERS) {
            return SettingRules::at($name, ViolationCode::TOO_MANY);
        }

        $violations = [];

        foreach ($value as $parameter => $argument) {

            $parameter = (string) $parameter;

            $code = match (true) {
                in_array(strtolower($parameter), self::RESERVED_PARAMETERS, true) => ViolationCode::RESERVED,
                !in_array($parameter, self::EXTRA_PARAMETERS, true)               => ViolationCode::NOT_ALLOWED,
                default                                                           => SettingRules::text($argument, self::MAX_PARAMETER_LENGTH),
            };

            array_push($violations, ...SettingRules::at(SettingRules::path($name, $parameter), $code));
        }

        return $violations;
    }
}
