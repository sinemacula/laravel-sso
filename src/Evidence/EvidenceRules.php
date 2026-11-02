<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Evidence;

use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\SettingRules;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;

/**
 * A connection's evidence policy (SSO-8.7): which authentication methods and
 * context classes it accepts, and which combinations of them count. Stored as
 * an array, by these names:
 *
 * - `amr`: the accepted OIDC methods, each an RFC 8176 value;
 * - `acr`: the accepted OIDC context classes;
 * - `authn_context_class_ref`: the accepted SAML context classes;
 * - `combinations`: what counts, at least one. Each names `amr`, a list of
 *   accepted methods every one of which the assertion must state, and `acr` or
 *   `authn_context_class_ref`, the one accepted class it must state, or both of
 *   the first two. A result satisfying any one combination counts. A
 *   combination naming nothing is refused, since it would count anything.
 *
 * `amr` and `acr` belong to every protocol but SAML, and
 * `authn_context_class_ref` to SAML alone; the other's is `unsupported`. A
 * driver an application registered is read as OIDC is, since a result's
 * authentication context states methods and one class whatever made it.
 *
 * `violations()` judges a policy to be written, with every violation named by
 * path and code and never by value; a policy of nothing is valid and accepts
 * nothing. `parse()` judges a stored one by the very same rules and answers
 * `null` for anything they refuse, so a malformed policy is insufficient rather
 * than an exception. `acceptedMethods()` compares exactly, whatever the case:
 * it answers the asserted methods the policy accepts, in their asserted order
 * and each once, when a combination is satisfied, and `null` when none is. An
 * asserted method the policy does not list never enters them, and judges
 * nothing.
 *
 * It holds nothing but one policy, for one call.
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
    private const array SETTINGS = [...self::PARTS, self::COMBINATIONS];

    /**
     * Constructor.
     *
     * @param  list<string>  $methods
     * @param  list<array{0: list<string>, 1: ?string}>  $combinations
     */
    private function __construct(

        /** The accepted RFC 8176 methods. */
        private array $methods,

        /** Each combination's required methods and required class. */
        private array $combinations,
    ) {}

    /**
     * Every violation of the policy on the protocol, by path and code: unknown
     * names first, then the accepted lists, then the combinations.
     *
     * @param  array<array-key, mixed>  $policy
     * @param  string  $protocol
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    public static function violations(array $policy, string $protocol): array
    {
        if ($policy === []) {
            return [];
        }

        return [...self::unknown($policy), ...self::accepted($policy, $protocol), ...self::combinations($policy, $protocol)];
    }

    /**
     * The rules of a stored policy on the protocol, or `null` when it accepts
     * nothing or is malformed.
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

        /** @var array{amr?: list<string>, combinations: list<array<string, list<string>|string>>} $stored */
        $combinations = array_map(static fn (array $combination): array => [$combination[self::AMR] ?? [], $combination[$class] ?? null], $stored[self::COMBINATIONS]);

        /** @var list<array{0: list<string>, 1: ?string}> $combinations */
        return new self($stored[self::AMR] ?? [], $combinations);
    }

    /**
     * The asserted methods the policy accepts, when the context satisfies a
     * combination; `null` when it satisfies none.
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
     * Whether what was accepted holds every method the combination requires,
     * and what was stated the class it requires, if any.
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
     * What the policy names that no policy has.
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
     * The code of what should be a list of at most the entries given.
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
     * The problems with a bounded list of context classes, each as a result
     * could state it and each once.
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
     * Every violation of what the policy says counts: at least one combination,
     * and at most `MAX_COMBINATIONS`.
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
     * Every violation of one combination: a map naming at least one part.
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
     * The problems with one part of a combination, which may only name what the
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
     * What the policy lists under the name: only a string can ever be chosen
     * from it.
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
