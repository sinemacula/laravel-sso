<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\SettingRules;
use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting;

/**
 * The settings of an OpenID Connect connection. A missing setting is not a
 * violation, so a connection may be saved before it is complete.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class OidcSettings implements ProtocolSettings
{
    /** @var list<string> How the client may authenticate at the token endpoint. */
    public const array CLIENT_AUTHENTICATIONS = ['client_secret_basic', 'client_secret_post', 'private_key_jwt'];

    /** @var list<string> The algorithms a client assertion may be pinned to (RFC 7523). */
    public const array CLIENT_ASSERTION_ALGORITHMS = [ClientAssertionAlgorithm::PS256, ClientAssertionAlgorithm::RS256, ClientAssertionAlgorithm::ES256];

    /** @var list<string> The ID token signature algorithms accepted, asymmetric only. */
    public const array ID_TOKEN_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512'];

    /** @var list<string> The extra authorisation parameters that may be set. */
    public const array EXTRA_PARAMETERS = ['prompt', 'acr_values', 'login_hint', 'ui_locales', 'claims_locales', 'display', 'domain_hint', 'hd'];

    /** @var list<string> The lower-case authorisation parameters only the flow sets. */
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

    /** @var int The most trusted audiences. */
    public const int MAX_TRUSTED_AUDIENCES = 10;

    /** @var int The longest trusted audience, in bytes. */
    public const int MAX_AUDIENCE_LENGTH = 255;

    /** @var int The longest `max_age`, in seconds (a week). */
    public const int MAX_MAX_AGE_SECONDS = 604800;

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
        'trusted_audiences'     => [],
        'fetch_userinfo'        => false,
        'metadata_refresh'      => true,
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
     * Read the settings, whatever their shape; a `null` value is not given.
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
     * The settings that may alter what existing subjects mean.
     *
     * @return list<string>
     */
    #[\Override]
    public static function subjectNames(): array
    {
        return OidcSetting::subjectNames();
    }

    /**
     * The setting that names the issuer.
     *
     * @return list<string>
     */
    #[\Override]
    public static function issuerNames(): array
    {
        return [OidcSetting::ISSUER->value];
    }

    /**
     * The operation whose freshness a change needs, or `null` for an unknown
     * name.
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
     * Every setting given or defaulted, in `OidcSetting` order; never a secret.
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
     * Every problem with the settings in `OidcSetting` order, then each unknown
     * name.
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
     * Whether the settings are valid and name every required value, including
     * the UserInfo endpoint while UserInfo is fetched.
     *
     * @return bool
     */
    #[\Override]
    public function isComplete(): bool
    {
        $required = [OidcSetting::ISSUER, OidcSetting::AUTHORIZATION_ENDPOINT, OidcSetting::TOKEN_ENDPOINT, OidcSetting::JWKS_URI, OidcSetting::CLIENT_ID];

        if (($this->values[OidcSetting::FETCH_USERINFO->value] ?? null) === true) {
            $required[] = OidcSetting::USERINFO_ENDPOINT;
        }

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
            OidcSetting::SCOPES              => self::scopes($name, $value),
            OidcSetting::ID_TOKEN_ALGORITHMS => SettingRules::allowedList($name, $value, self::ID_TOKEN_ALGORITHMS),
            OidcSetting::EXTRA_PARAMETERS    => self::extraParameters($name, $value),
            OidcSetting::TRUSTED_AUDIENCES   => self::trustedAudiences($name, $value),
            default                          => SettingRules::at($name, self::code($setting, $value)),
        };
    }

    /**
     * The problem with one single-valued setting, or `null`. The issuer is kept
     * exactly, so it allows no query.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Enums\OidcSetting  $setting
     * @param  mixed  $value
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    private static function code(OidcSetting $setting, mixed $value): ?ViolationCode
    {
        return match ($setting) {
            OidcSetting::ISSUER                                                                  => SettingRules::url($value, false),
            OidcSetting::RETURNS_ISS, OidcSetting::FETCH_USERINFO, OidcSetting::METADATA_REFRESH => SettingRules::boolean($value),
            OidcSetting::CLIENT_ID                                                               => SettingRules::text($value, self::MAX_CLIENT_ID_LENGTH),
            OidcSetting::CLIENT_SECRET                                                           => ViolationCode::RESERVED,
            OidcSetting::CLIENT_AUTHENTICATION                                                   => SettingRules::choice($value, self::CLIENT_AUTHENTICATIONS),
            OidcSetting::CLIENT_ASSERTION_ALGORITHM                                              => SettingRules::choice($value, self::CLIENT_ASSERTION_ALGORITHMS),
            OidcSetting::MAX_AGE                                                                 => self::maxAge($value),
            default                                                                              => SettingRules::url($value),
        };
    }

    /**
     * The scopes: at most twenty distinct scope tokens, including `openid`.
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
     * The extra parameters: at most ten allow-listed names; a name the flow
     * controls, in any case, is `reserved`.
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

    /**
     * The trusted audiences: at most ten distinct strings with no whitespace.
     *
     * @param  string  $name
     * @param  mixed  $value
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    private static function trustedAudiences(string $name, mixed $value): array
    {
        if (SettingRules::list($value) !== null || !is_array($value)) {
            return SettingRules::at($name, ViolationCode::INVALID_TYPE);
        }

        if (count($value) > self::MAX_TRUSTED_AUDIENCES) {
            return SettingRules::at($name, ViolationCode::TOO_MANY);
        }

        $violations = [];

        foreach ($value as $index => $audience) {

            $code = SettingRules::text($audience, self::MAX_AUDIENCE_LENGTH, false)
                ?? (array_search($audience, $value, true) !== $index ? ViolationCode::DUPLICATE : null);

            array_push($violations, ...SettingRules::at($name . '.' . $index, $code));
        }

        return $violations;
    }

    /**
     * The `max_age`: an integer from 0 to a week, in seconds.
     *
     * @param  mixed  $value
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    private static function maxAge(mixed $value): ?ViolationCode
    {
        if (!is_int($value)) {
            return ViolationCode::INVALID_TYPE;
        }

        return $value < 0 || $value > self::MAX_MAX_AGE_SECONDS ? ViolationCode::NOT_ALLOWED : null;
    }
}
