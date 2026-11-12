<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver;

/**
 * A connection's attribute mapping: each result attribute keyed by the SAML
 * attribute or OIDC claim it is read from.
 *
 * Mapped values are profile data only and never select an identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AttributeMapping
{
    /** @var string The path every violation is reported under. */
    public const string PATH = 'attribute_mapping';

    /** @var list<string> The standard targets, in the order the result lists them. */
    public const array STANDARD_TARGETS = ['email', 'given_name', 'family_name', 'display_name', 'groups'];

    /** @var list<string> The targets that would name one of the result's own fields. */
    public const array RESERVED_TARGETS = [
        'issuer',
        'subject',
        'name_id',
        'name_id_format',
        'connection',
        'connection_id',
        'tenant',
        'tenant_id',
        'protocol',
        'application',
        'purpose',
        'authentication_context',
        'auth_time',
        'amr',
        'acr',
        'session',
        'session_id',
        'sid',
        'session_index',
        'email_verified',
        'domain_verified',
        'identity',
        'identity_id',
        'reference',
        'linking_email',
    ];

    /** @var list<string> The OIDC claims and parameters that are protocol values or tokens, never a source. */
    public const array RESERVED_OIDC_SOURCES = [
        'iss',
        'sub',
        'aud',
        'exp',
        'iat',
        'nbf',
        'jti',
        'auth_time',
        'nonce',
        'acr',
        'amr',
        'azp',
        'at_hash',
        'c_hash',
        's_hash',
        'sid',
        'email_verified',
        'access_token',
        'id_token',
        'refresh_token',
        'code',
        'state',
        'client_id',
    ];

    /** @var int The longest source, in bytes. */
    public const int MAX_SOURCE_LENGTH = 1024;

    /** @var string A custom target's form. */
    private const string CUSTOM_TARGET = '/^[a-z][a-z0-9_]{0,63}$/D';

    /** @var string The target whose values are always a list. */
    private const string GROUPS = 'groups';

    /** @var array<string, array<string, string>> The default mapping of each protocol the package ships. */
    private const array DEFAULTS = [
        OidcDriver::NAME => [
            'email'        => 'email',
            'given_name'   => 'given_name',
            'family_name'  => 'family_name',
            'display_name' => 'name',
            'groups'       => 'groups',
        ],
        Saml2Driver::NAME => [
            'email'        => 'urn:oid:0.9.2342.19200300.100.1.3',
            'given_name'   => 'urn:oid:2.5.4.42',
            'family_name'  => 'urn:oid:2.5.4.4',
            'display_name' => 'urn:oid:2.16.840.1.113730.3.1.241',
            'groups'       => 'urn:oid:1.3.6.1.4.1.5923.1.5.1.1',
        ],
    ];

    /**
     * Constructor.
     *
     * @param  string  $protocol
     * @param  array<array-key, mixed>  $mapping
     * @param  \SineMacula\Laravel\Sso\Connections\MappingLimits  $limits
     */
    private function __construct(

        /** The protocol of the connection the mapping belongs to. */
        private string $protocol,

        /** Each target by its source, as given. */
        private array $mapping,

        /** The caps on what the mapping carries. */
        private MappingLimits $limits,
    ) {}

    /**
     * The protocol's default mapping; none for a protocol the package does not
     * ship.
     *
     * @param  string  $protocol
     * @return array<string, string>
     */
    public static function defaults(string $protocol): array
    {
        return self::DEFAULTS[$protocol] ?? [];
    }

    /**
     * Never throws on bad input; `violations()` reports it.
     *
     * @param  string  $protocol
     * @param  array<array-key, mixed>  $mapping
     * @param  \SineMacula\Laravel\Sso\Connections\MappingLimits  $limits
     * @return self
     */
    public static function fromArray(string $protocol, array $mapping, MappingLimits $limits): self
    {
        return new self($protocol, $mapping, $limits);
    }

    /**
     * The mapping to store.
     *
     * @return array<array-key, mixed>
     */
    public function toArray(): array
    {
        return $this->mapping;
    }

    /**
     * Whether the name has a custom target's form and is neither standard nor
     * reserved.
     *
     * @param  string  $target
     * @return bool
     */
    public static function isCustomTarget(string $target): bool
    {
        return self::target($target) === null && !in_array($target, self::STANDARD_TARGETS, true);
    }

    /**
     * Every problem with the mapping, in the order given, never echoing a
     * source.
     *
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     *
     * @throws \InvalidArgumentException
     */
    public function violations(): array
    {
        $declared   = $this->limits->customAttributes();
        $violations = [];

        foreach ($this->mapping as $target => $source) {

            $target = (string) $target;
            $code   = self::target($target) ?? self::undeclared($target, $declared) ?? $this->source($source);

            array_push($violations, ...SettingRules::at(SettingRules::path(self::PATH, $target), $code));
        }

        return $violations;
    }

    /**
     * The capped profile data read from validated claims or attributes; a
     * custom target no longer declared keeps nothing.
     *
     * @param  array<string, mixed>  $values
     * @return array<string, list<string>|string>
     *
     * @throws \InvalidArgumentException
     */
    public function map(array $values): array
    {
        $length   = $this->limits->maxValueLength();
        $most     = $this->limits->maxValues();
        $declared = $this->limits->customAttributes();
        $mapped   = [];

        foreach ($this->mapping as $target => $source) {

            $target = (string) $target;

            if (self::undeclared($target, $declared) !== null || !is_string($source) || !array_key_exists($source, $values)) {
                continue;
            }

            $value = self::profileValue($target, $values[$source], $length, $most);

            if ($value === null) {
                continue;
            }

            $mapped[$target] = $value;
        }

        return $mapped;
    }

    /**
     * Why the target cannot be mapped to, or `null` when it can.
     *
     * @param  string  $target
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    private static function target(string $target): ?ViolationCode
    {
        return match (true) {
            in_array($target, self::RESERVED_TARGETS, true) => ViolationCode::RESERVED,
            default                                         => preg_match(self::CUSTOM_TARGET, $target) === 1 ? null : ViolationCode::INVALID_FORMAT,
        };
    }

    /**
     * `not_allowed` unless the target is standard or declared by the
     * application.
     *
     * @param  string  $target
     * @param  list<string>  $declared
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    private static function undeclared(string $target, array $declared): ?ViolationCode
    {
        return in_array($target, self::STANDARD_TARGETS, true) || in_array($target, $declared, true) ? null : ViolationCode::NOT_ALLOWED;
    }

    /**
     * Why the source cannot be read from, or `null`; over OIDC it must not be a
     * protocol value or token.
     *
     * @param  mixed  $source
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    private function source(mixed $source): ?ViolationCode
    {
        $code = SettingRules::text($source, self::MAX_SOURCE_LENGTH);

        if ($code !== null) {
            return $code;
        }

        return $this->protocol === OidcDriver::NAME && in_array($source, self::RESERVED_OIDC_SOURCES, true) ? ViolationCode::RESERVED : null;
    }

    /**
     * The capped value a target keeps: the first string for a standard target
     * other than `groups`, else a string or list. `null` for none.
     *
     * @param  string  $target
     * @param  mixed  $value
     * @param  int  $length
     * @param  int  $most
     * @return list<string>|string|null
     */
    private static function profileValue(string $target, mixed $value, int $length, int $most): array|string|null
    {
        $strings = self::strings($value);

        if ($strings === []) {
            return null;
        }

        $cut  = static fn (string $string): string => mb_substr(mb_scrub($string, 'UTF-8'), 0, $length, 'UTF-8');
        $list = array_map($cut, array_slice($strings, 0, $most));

        return match (true) {
            $target === self::GROUPS                        => $list,
            in_array($target, self::STANDARD_TARGETS, true) => $cut($strings[0]),
            is_string($value)                               => $cut($value),
            default                                         => $list,
        };
    }

    /**
     * The value as a list of strings, dropping anything else.
     *
     * @param  mixed  $value
     * @return list<string>
     */
    private static function strings(mixed $value): array
    {
        if (is_array($value)) {
            return array_values(array_filter($value, is_string(...)));
        }

        return is_string($value) ? [$value] : [];
    }
}
