<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Evidence;

use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\SettingRules;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;

/**
 * A connection's evidence policy: the accepted methods and context classes, and
 * which combinations of them count.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EvidenceRules
{
    /** @var string The accepted OIDC methods, as a policy names them. */
    public const string AMR = 'amr';

    /** @var string The accepted OIDC context classes, as a policy names them. */
    public const string ACR = 'acr';

    /** @var string The accepted SAML context classes, as a policy names them. */
    public const string AUTHN_CONTEXT_CLASS_REF = 'authn_context_class_ref';

    /** @var string What counts, as a policy names it. */
    public const string COMBINATIONS = 'combinations';

    /** @var string How long this connection accepts evidence, as a policy names it. */
    public const string MAX_AGE_SECONDS = 'max_age_seconds';

    /** @var int The most values one list may name. */
    public const int MAX_VALUES = 32;

    /** @var int The most combinations a policy may name. */
    public const int MAX_COMBINATIONS = 32;

    /** @var list<string> The authentication method reference values RFC 8176 registers. */
    public const array RFC_8176_METHODS = [
        'face', 'fpt', 'geo', 'hwk', 'iris', 'kba', 'mca', 'mfa', 'otp', 'pin',
        'pwd', 'rba', 'retina', 'sc', 'sms', 'swk', 'tel', 'user', 'vbm', 'wia',
    ];

    /** @var list<string> What a combination may name. */
    private const array PARTS = [self::AMR, self::ACR, self::AUTHN_CONTEXT_CLASS_REF];

    /** @var list<string> What a policy may name. */
    private const array SETTINGS = [...self::PARTS, self::COMBINATIONS, self::MAX_AGE_SECONDS];

    /**
     * Constructor.
     *
     * @param  list<string>  $methods
     * @param  list<array{0: list<string>, 1: ?string}>  $combinations
     * @param  ?int  $maxAgeSeconds
     */
    private function __construct(

        /** The accepted RFC 8176 methods. */
        private array $methods,

        /** Each combination's required methods and required class. */
        private array $combinations,

        /** How long this connection accepts evidence, as stored. */
        private ?int $maxAgeSeconds = null,
    ) {}

    /**
     * Every violation of the policy on the protocol, by path and code, never by
     * value; an empty policy is valid.
     *
     * @param  array<array-key, mixed>  $policy
     * @param  string  $protocol
     * @param  ?int  $ceiling
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    public static function violations(array $policy, string $protocol, ?int $ceiling = null): array
    {
        if ($policy === []) {
            return [];
        }

        return [
            ...self::unknown($policy),
            ...self::accepted($policy, $protocol),
            ...self::combinations($policy, $protocol),
            ...SettingRules::at(self::MAX_AGE_SECONDS, self::maxAgeCode($policy, $ceiling)),
        ];
    }

    /**
     * The rules of a stored policy, or `null` when it accepts nothing or is
     * malformed.
     *
     * The ceiling is not checked here, so lowering it later never makes a
     * stored policy malformed.
     *
     * @param  mixed  $stored
     * @param  string  $protocol
     * @return ?self
     */
    public static function parse(mixed $stored, string $protocol): ?self
    {
        if (!is_array($stored) || $stored === [] || self::violations($stored, $protocol) !== []) {
            return null;
        }

        $class = self::isSaml($protocol) ? self::AUTHN_CONTEXT_CLASS_REF : self::ACR;

        /** @var array{amr?: list<string>, combinations: list<array<string, list<string>|string>>, max_age_seconds?: int} $stored */
        $combinations = array_map(static fn (array $combination): array => [$combination[self::AMR] ?? [], $combination[$class] ?? null], $stored[self::COMBINATIONS]);

        /** @var ?int $maxAge */
        $maxAge = $stored[self::MAX_AGE_SECONDS] ?? null;

        /** @var list<array{0: list<string>, 1: ?string}> $combinations */
        return new self($stored[self::AMR] ?? [], $combinations, $maxAge);
    }

    /**
     * The connection's maximum age, clamped to the current ceiling.
     *
     * @param  int  $ceiling
     * @return int
     */
    public function maxAgeSeconds(int $ceiling): int
    {
        return min($this->maxAgeSeconds ?? $ceiling, $ceiling);
    }

    /**
     * The asserted methods the policy accepts, in asserted order, or `null`
     * when no combination is satisfied.
     *
     * @param  \SineMacula\Laravel\Sso\Results\AuthenticationContext  $context
     * @return ?list<string>
     */
    public function acceptedMethods(AuthenticationContext $context): ?array
    {
        $methods = array_values(array_unique(array_filter($context->methods, fn (string $method): bool => in_array($method, $this->methods, true))));

        foreach ($this->combinations as [$required, $class]) {

            if (self::isSatisfied($required, $class, $methods, $context->contextClass)) {
                return $methods;
            }
        }

        return null;
    }

    /**
     * Whether the accepted methods and stated class satisfy one combination.
     *
     * @param  list<string>  $required
     * @param  ?string  $class
     * @param  list<string>  $methods
     * @param  ?string  $stated
     * @return bool
     */
    private static function isSatisfied(array $required, ?string $class, array $methods, ?string $stated): bool
    {
        return array_diff($required, $methods) === [] && ($class === null || $class === $stated);
    }

    /**
     * The maximum age's violation code, or `null` when absent or valid.
     *
     * @param  array<array-key, mixed>  $policy
     * @param  ?int  $ceiling
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    private static function maxAgeCode(array $policy, ?int $ceiling): ?ViolationCode
    {
        if (!array_key_exists(self::MAX_AGE_SECONDS, $policy)) {
            return null;
        }

        $value = $policy[self::MAX_AGE_SECONDS];

        return match (true) {
            !is_int($value)                        => ViolationCode::INVALID_TYPE,
            $value < 1                             => ViolationCode::NOT_ALLOWED,
            $ceiling !== null && $value > $ceiling => ViolationCode::NOT_ALLOWED,
            default                                => null,
        };
    }

    /**
     * Whether the protocol is the package's own SAML.
     *
     * @param  string  $protocol
     * @return bool
     */
    private static function isSaml(string $protocol): bool
    {
        return $protocol === Saml2Driver::NAME;
    }

    /**
     * The accepted lists the protocol has.
     *
     * @param  string  $protocol
     * @return list<string>
     */
    private static function supported(string $protocol): array
    {
        return self::isSaml($protocol) ? [self::AUTHN_CONTEXT_CLASS_REF] : [self::AMR, self::ACR];
    }

    /**
     * The policy's unknown names.
     *
     * @param  array<array-key, mixed>  $policy
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    private static function unknown(array $policy): array
    {
        $violations = [];

        foreach (array_keys($policy) as $name) {

            if (in_array($name, self::SETTINGS, true)) {
                continue;
            }

            array_push($violations, ...SettingRules::at(SettingRules::path(null, $name), ViolationCode::UNKNOWN));
        }

        return $violations;
    }

    /**
     * Every violation of the accepted lists the policy names.
     *
     * @param  array<array-key, mixed>  $policy
     * @param  string  $protocol
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    private static function accepted(array $policy, string $protocol): array
    {
        $violations = [];

        foreach (self::PARTS as $name) {

            if (!array_key_exists($name, $policy)) {
                continue;
            }

            array_push($violations, ...match (true) {
                !in_array($name, self::supported($protocol), true) => SettingRules::at($name, ViolationCode::UNSUPPORTED),
                $name === self::AMR                                => self::methods($name, $policy[$name], self::RFC_8176_METHODS, false),
                default                                            => self::classes($name, $policy[$name]),
            });
        }

        return $violations;
    }

    /**
     * The violation code of a list bounded by `$max` entries.
     *
     * @param  mixed  $value
     * @param  int  $max
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    private static function listCode(mixed $value, int $max): ?ViolationCode
    {
        return match (true) {
            SettingRules::list($value) !== null      => ViolationCode::INVALID_TYPE,
            is_array($value) && count($value) > $max => ViolationCode::TOO_MANY,
            default                                  => null,
        };
    }

    /**
     * The problems with a bounded list of methods from those allowed.
     *
     * @param  string  $path
     * @param  mixed  $value
     * @param  array<array-key, mixed>  $allowed
     * @param  bool  $required
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    private static function methods(string $path, mixed $value, array $allowed, bool $required): array
    {
        $code = self::listCode($value, self::MAX_VALUES);

        return $code === null ? SettingRules::allowedList($path, $value, $allowed, $required) : SettingRules::at($path, $code);
    }

    /**
     * The problems with a bounded list of unique context classes.
     *
     * @param  string  $path
     * @param  mixed  $value
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    private static function classes(string $path, mixed $value): array
    {
        $code = self::listCode($value, self::MAX_VALUES);

        if ($code !== null || !is_array($value)) {
            return SettingRules::at($path, $code ?? ViolationCode::INVALID_TYPE);
        }

        $violations = [];
        $seen       = [];

        foreach ($value as $index => $entry) {

            $code = SettingRules::text($entry, AuthenticationContext::MAX_VALUE_LENGTH) ?? (in_array($entry, $seen, true) ? ViolationCode::DUPLICATE : null);

            $seen[] = $entry;

            array_push($violations, ...SettingRules::at($path . '.' . $index, $code));
        }

        return $violations;
    }

    /**
     * Every violation of the combinations: one to `MAX_COMBINATIONS` of them.
     *
     * @param  array<array-key, mixed>  $policy
     * @param  string  $protocol
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    private static function combinations(array $policy, string $protocol): array
    {
        $value = $policy[self::COMBINATIONS] ?? [];
        $code  = $value === [] ? ViolationCode::REQUIRED : self::listCode($value, self::MAX_COMBINATIONS);

        if ($code !== null || !is_array($value)) {
            return SettingRules::at(self::COMBINATIONS, $code ?? ViolationCode::INVALID_TYPE);
        }

        $violations = [];

        foreach ($value as $index => $combination) {
            array_push($violations, ...self::combination(self::COMBINATIONS . '.' . $index, $combination, $policy, $protocol));
        }

        return $violations;
    }

    /**
     * Every violation of one combination, a map naming at least one part.
     *
     * @param  string  $path
     * @param  mixed  $combination
     * @param  array<array-key, mixed>  $policy
     * @param  string  $protocol
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    private static function combination(string $path, mixed $combination, array $policy, string $protocol): array
    {
        if ($combination === []) {
            return SettingRules::at($path, ViolationCode::REQUIRED);
        }

        if (!is_array($combination) || array_is_list($combination)) {
            return SettingRules::at($path, ViolationCode::INVALID_TYPE);
        }

        $violations = [];

        foreach ($combination as $name => $value) {
            array_push($violations, ...self::part(SettingRules::path($path, $name), $name, $value, $policy, $protocol));
        }

        return $violations;
    }

    /**
     * The problems with one combination part, which may name only what the
     * policy accepts.
     *
     * @param  string  $path
     * @param  int|string  $name
     * @param  mixed  $value
     * @param  array<array-key, mixed>  $policy
     * @param  string  $protocol
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    private static function part(string $path, int|string $name, mixed $value, array $policy, string $protocol): array
    {
        return match (true) {
            !in_array($name, self::PARTS, true)                => SettingRules::at($path, ViolationCode::UNKNOWN),
            !in_array($name, self::supported($protocol), true) => SettingRules::at($path, ViolationCode::UNSUPPORTED),
            $name === self::AMR                                => self::methods($path, $value, self::listed($policy, self::AMR), true),
            default                                            => SettingRules::at($path, SettingRules::choice($value, self::listed($policy, $name))),
        };
    }

    /**
     * What the policy lists under the name, or an empty list.
     *
     * @param  array<array-key, mixed>  $policy
     * @param  string  $name
     * @return array<array-key, mixed>
     */
    private static function listed(array $policy, string $name): array
    {
        $listed = $policy[$name] ?? [];

        return is_array($listed) ? $listed : [];
    }
}
