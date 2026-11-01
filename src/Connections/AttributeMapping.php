<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver;

/**
 * A connection's attribute mapping (SSO-2.10): each attribute of the result,
 * its target, by the SAML attribute or OIDC claim it is read from, its source.
 *
 * The standard targets are `email`, `given_name`, `family_name`, `display_name`
 * and `groups`; an application adds custom targets, each a lower-case name (a
 * letter, then up to 63 letters, digits or underscores), up to
 * `MappingLimits::maxCustomAttributes()` of them. A target never names one of
 * the result's own fields (its issuer, subject, connection, tenant,
 * authentication context, session or identity), and, over OIDC, a source never
 * names a protocol value or a token, so a mapping can neither forge what the
 * package verified nor carry a credential.
 *
 * Mapped values are profile data: each is cut to
 * `MappingLimits::maxValueLength()` characters, a list keeps at most
 * `MappingLimits::maxValues()` strings, groups are passed on as a list without
 * interpretation, and nothing mapped ever selects an identity (SSO-8.2) or
 * gives the email a link is made by (SSO-8.8).
 *
 * Built from what was given or stored with `fromArray()`, which never throws on
 * bad input: `violations()` reports every problem at `attribute_mapping.` and
 * the target, never echoing a source.
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

    /** @var list<string> The targets that would name one of the result's own fields (SSO-2.10). */
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

    /** @var string A custom target: a lower-case letter, then up to 63 lower-case letters, digits or underscores. */
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
     * The default mapping of the protocol: the OIDC standard claims, or the
     * common SAML attributes by their OIDs; none for another protocol.
     *
     * @param  string  $protocol
     * @return array<string, string>
     */
    public static function defaults(string $protocol): array
    {
        return self::DEFAULTS[$protocol] ?? [];
    }

    /**
     * The mapping the values give, whatever their shape.
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
     * The mapping to store: each target by its source.
     *
     * @return array<array-key, mixed>
     */
    public function toArray(): array
    {
        return $this->mapping;
    }

    /**
     * Every problem with the mapping, target by target in the order given, then
     * `too_many` at `attribute_mapping` when it declares more custom targets
     * than allowed.
     *
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     *
     * @throws \InvalidArgumentException
     */
    public function violations(): array
    {
        $violations = [];
        $custom     = 0;

        foreach ($this->mapping as $target => $source) {

            $target = (string) $target;
            $code   = self::target($target) ?? $this->source($source);

            if ($code === null && !in_array($target, self::STANDARD_TARGETS, true)) {
                $custom++;
            }

            array_push($violations, ...SettingRules::at(SettingRules::path(self::PATH, $target), $code));
        }

        if ($custom > $this->limits->maxCustomAttributes()) {
            array_push($violations, ...SettingRules::at(self::PATH, ViolationCode::TOO_MANY));
        }

        return $violations;
    }

    /**
     * The profile data the mapping reads from validated claims or attributes,
     * for each target whose source is present and holds a string.
     *
     * A standard target other than `groups` takes the string, or the first
     * string of a list. `groups` and custom targets keep a string as it is
     * (`groups` as a list of one), or a list of at most
     * `MappingLimits::maxValues()` strings in order, anything not a string
     * dropped. Every string is cut to `MappingLimits::maxValueLength()`
     * characters. A target with nothing to keep is left out.
     *
     * @param  array<string, mixed>  $values
     * @return array<string, list<string>|string>
     *
     * @throws \InvalidArgumentException
     */
    public function map(array $values): array
    {
        $length = $this->limits->maxValueLength();
        $most   = $this->limits->maxValues();
        $mapped = [];

        foreach ($this->mapping as $target => $source) {

            $target = (string) $target;

            if (self::target($target) !== null || !is_string($source) || !array_key_exists($source, $values)) {
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
     * Why the target cannot be mapped to, or `null` when it can: one of the
     * result's own fields is `reserved`, and a name that is neither standard
     * nor a custom target's is `invalid_format`.
     *
     * @param  string  $target
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    private static function target(string $target): ?ViolationCode
    {
        return match (true) {
            in_array($target, self::RESERVED_TARGETS, true) => ViolationCode::RESERVED,
            in_array($target, self::STANDARD_TARGETS, true) => null,
            default                                         => preg_match(self::CUSTOM_TARGET, $target) === 1 ? null : ViolationCode::INVALID_FORMAT,
        };
    }

    /**
     * Why the source cannot be read from, or `null` when it can: a name of at
     * most 1024 bytes with no control character that, over OIDC, is not a
     * protocol value or a token.
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
     * The value a target keeps of what its source holds, or `null` when it
     * keeps nothing.
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
     * The strings a value holds: the value itself when it is one, the strings
     * of a list in order, or none.
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
