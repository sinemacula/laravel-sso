<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2;

use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\SettingRules;
use SineMacula\Laravel\Sso\Contracts\ProtocolSettings;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;

/**
 * The settings of a SAML 2.0 connection (SSO-2.3, SSO-5.3, SSO-5.8, SSO-6.7 to
 * SSO-6.9), named by `Enums\Saml2Setting`, which also classifies a change to
 * each.
 *
 * - `idp_entity_id`: the identity provider's entity id, an absolute `https:`,
 *   `http:` or `urn:` URI of at most 1024 bytes with no whitespace.
 * - `sso_url`: its single sign-on URL, an `https` URL with a host and no
 *   userinfo or fragment, of at most 2048 bytes; `sso_binding`: `http_redirect`
 *   (the default) or `http_post`.
 * - `subject_source`: `name_id` (the default) or `attribute`, which needs
 *   `subject_attribute`, the attribute holding a stable identifier (SSO-6.9);
 *   `name_id_format`: `persistent` (the default), `email` or `unspecified`,
 *   never `transient`.
 * - `sign_authn_requests`, `force_authn` (both off by default) and
 *   `want_assertions_signed` (on by default).
 * - `require_encrypted_assertions` (off by default), which may be on only while
 *   `sso.features.encrypted_assertions` is (SSO-6.8).
 * - `signature_algorithms`: RSA over SHA-256, SHA-384 or SHA-512, all by
 *   default and never SHA-1; `encryption_algorithms`: RSA-OAEP key transport
 *   and AES-128-GCM or AES-192-GCM by default, AES-CBC only when listed, never
 *   RSA 1.5, with at least one key transport and one data algorithm (SSO-6.7).
 *   These are what the SAML library verifies and decrypts on PHP 8.3 with
 *   `saml2` 6: SAML is RSA only, every other signature algorithm (ECDSA,
 *   RSA-PSS) and AES-256-GCM refused as `not_allowed`, as every SAML key use
 *   refuses an elliptic curve key; ECDSA and AES-256-GCM arrive when the PHP
 *   floor moves to 8.5 and `saml2` 7 is stable (`docs/design/saml-library.md`).
 * - `requested_authn_context`: up to ten authentication context classes (none
 *   by default), requested with `Comparison="exact"` and required of the
 *   response, which must assert one of them (SSO-6.10).
 * - `max_authentication_age_seconds`: how old the provider's `AuthnInstant` may
 *   be, 60 seconds to a week (none by default).
 * - `idp_initiated` (off by default), which may be on only while
 *   `sso.features.idp_initiated` is, and then needs `idp_initiated_start_url`,
 *   an `https` URL as `sso_url` (SSO-5.8).
 * - `metadata_url`: the `https` URL the provider's metadata is fetched from, as
 *   `sso_url`; `metadata_refresh`: left unset, the schedule refreshes a
 *   connection with a `metadata_url` exactly while it has a metadata signing
 *   anchor, so adding or removing the anchor needs no other change; `true`
 *   refreshes it without one, delegating trust to the URL and its TLS, and
 *   requires `metadata_url`; and `false` opts out (SSO-2.8,
 *   `Metadata\SamlRefreshRule`). The schedule runs while
 *   `sso.features.metadata_refresh` is on. An administrator's refresh stays
 *   available; a connection with neither an anchor nor `true` has no stale limit,
 *   and `false` on an anchored one leaves the limit in force.
 *
 * A missing setting is not a violation, so a connection may be saved before it
 * is complete; `isComplete()` says when it is. What is stored holds every
 * setting given or defaulted, defaults applied, `metadata_refresh` only when it
 * is given. It holds no secret: a SAML connection's key pairs and trusted
 * certificates are kept with its keys.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Saml2Settings implements ProtocolSettings
{
    /** @var list<string> The signature algorithms accepted (SSO-6.7), in the order they are preferred. */
    public const array SIGNATURE_ALGORITHMS = [
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
    ];

    /** @var list<string> The key transport algorithms accepted: RSA-OAEP, never RSA 1.5. */
    public const array KEY_TRANSPORT_ALGORITHMS = [
        'http://www.w3.org/2009/xmlenc11#rsa-oaep',
        'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
    ];

    /** @var list<string> The data encryption algorithms accepted by default: AES-GCM, but AES-256-GCM. */
    public const array DATA_ENCRYPTION_ALGORITHMS = [
        'http://www.w3.org/2009/xmlenc11#aes128-gcm',
        'http://www.w3.org/2009/xmlenc11#aes192-gcm',
    ];

    /** @var list<string> The data encryption algorithms accepted only when listed: AES-CBC. */
    public const array CBC_ALGORITHMS = [
        'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
        'http://www.w3.org/2001/04/xmlenc#aes192-cbc',
        'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
    ];

    /** @var list<string> The bindings an `AuthnRequest` may be sent by. */
    public const array BINDINGS = ['http_redirect', 'http_post'];

    /** @var list<string> Where the subject may come from. */
    public const array SUBJECT_SOURCES = ['name_id', 'attribute'];

    /** @var list<string> The NameID formats that may be requested; never `transient`. */
    public const array NAME_ID_FORMATS = ['persistent', 'email', 'unspecified'];

    /** @var int The longest entity id, attribute name or context class, in bytes. */
    public const int MAX_VALUE_LENGTH = 1024;

    /** @var int The most authentication context classes that may be requested. */
    public const int MAX_AUTHN_CONTEXTS = 10;

    /** @var int The shortest maximum authentication age, in seconds. */
    public const int MIN_AUTHENTICATION_AGE_SECONDS = 60;

    /** @var int The longest maximum authentication age, in seconds (a week). */
    public const int MAX_AUTHENTICATION_AGE_SECONDS = 604800;

    /** @var array<string, list<string>> The values each setting of a fixed choice allows, by setting. */
    private const array CHOICES = [
        'sso_binding'    => self::BINDINGS,
        'subject_source' => self::SUBJECT_SOURCES,
        'name_id_format' => self::NAME_ID_FORMATS,
    ];

    /** @var array<string, \SineMacula\Laravel\Sso\Config\Enums\Feature> The feature each switch needs on before it may be, by setting. */
    private const array GATES = [
        'require_encrypted_assertions' => Feature::ENCRYPTED_ASSERTIONS,
        'idp_initiated'                => Feature::IDP_INITIATED,
    ];

    /** @var array<string, mixed> The value of each setting that has a default, by name. */
    private const array DEFAULTS = [
        'sso_binding'                  => 'http_redirect',
        'subject_source'               => 'name_id',
        'name_id_format'               => 'persistent',
        'sign_authn_requests'          => false,
        'want_assertions_signed'       => true,
        'require_encrypted_assertions' => false,
        'signature_algorithms'         => self::SIGNATURE_ALGORITHMS,
        'encryption_algorithms'        => [...self::KEY_TRANSPORT_ALGORITHMS, ...self::DATA_ENCRYPTION_ALGORITHMS],
        'force_authn'                  => false,
        'requested_authn_context'      => [],
        'idp_initiated'                => false,
    ];

    /** @var string An entity id that is a URN: `urn:`, a namespace identifier, `:` and the rest. */
    private const string URN = '/^urn:[A-Za-z0-9][A-Za-z0-9-]{0,31}:\S+$/iD';

    /** @var string An entity id that is an HTTP or HTTPS URL. */
    private const string HTTP_URI = '#^https?://#i';

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
     * None: a SAML connection's secrets are its private keys, kept with its
     * keys.
     *
     * @return list<string>
     */
    #[\Override]
    public static function secretNames(): array
    {
        return [];
    }

    /**
     * The settings a change to which may alter what existing subjects mean.
     *
     * @return list<string>
     */
    #[\Override]
    public static function subjectNames(): array
    {
        return Saml2Setting::subjectNames();
    }

    /**
     * The setting that names the issuer.
     *
     * @return list<string>
     */
    #[\Override]
    public static function issuerNames(): array
    {
        return [Saml2Setting::IDP_ENTITY_ID->value];
    }

    /**
     * The operation whose freshness a change to the setting needs, as
     * `Saml2Setting` classifies it; `null` for a name it does not have.
     *
     * @param  string  $name
     * @return ?\SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation
     */
    #[\Override]
    public static function freshnessFor(string $name): ?FreshnessOperation
    {
        return Saml2Setting::tryFrom($name)?->freshness();
    }

    /**
     * Every setting given or with a default, defaults applied, in the order
     * `Saml2Setting` names them.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function toArray(): array
    {
        $values = [];

        foreach (Saml2Setting::cases() as $setting) {

            $name = $setting->value;

            if (array_key_exists($name, $this->values)) {
                $values[$name] = $this->values[$name];
            } elseif (array_key_exists($name, self::DEFAULTS)) {
                $values[$name] = self::DEFAULTS[$name];
            }
        }

        return $values;
    }

    /**
     * Every problem with the settings, in the order `Saml2Setting` names them,
     * then each name it does not have, as `unknown`.
     *
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function violations(): array
    {
        $violations = [];

        foreach (Saml2Setting::cases() as $setting) {
            array_push($violations, ...$this->check($setting));
        }

        foreach (array_keys($this->values) as $name) {

            if (Saml2Setting::tryFrom((string) $name) !== null) {
                continue;
            }

            array_push($violations, ...SettingRules::at(SettingRules::path(null, $name), ViolationCode::UNKNOWN));
        }

        return $violations;
    }

    /**
     * Whether the settings are valid, and name the identity provider's entity
     * id and single sign-on URL.
     *
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function isComplete(): bool
    {
        return $this->violations() === []
            && array_key_exists(Saml2Setting::IDP_ENTITY_ID->value, $this->values)
            && array_key_exists(Saml2Setting::SSO_URL->value, $this->values);
    }

    /**
     * The problems with one setting: its value's, or, when it is not given, the
     * requirement another setting puts on it.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting  $setting
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     *
     * @throws \InvalidArgumentException
     */
    private function check(Saml2Setting $setting): array
    {
        $name = $setting->value;

        if (!array_key_exists($name, $this->values)) {
            return SettingRules::at($name, $this->requirement($setting));
        }

        $value = $this->values[$name];

        return match ($setting) {
            Saml2Setting::SIGNATURE_ALGORITHMS    => SettingRules::allowedList($name, $value, self::SIGNATURE_ALGORITHMS),
            Saml2Setting::ENCRYPTION_ALGORITHMS   => self::encryptionAlgorithms($name, $value),
            Saml2Setting::REQUESTED_AUTHN_CONTEXT => self::authnContexts($name, $value),
            default                               => SettingRules::at($name, $this->code($setting, $value)),
        };
    }

    /**
     * The problem with the value of a setting that holds a single value, or
     * `null` when it has none.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting  $setting
     * @param  mixed  $value
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     *
     * @throws \InvalidArgumentException
     */
    private function code(Saml2Setting $setting, mixed $value): ?ViolationCode
    {
        return match ($setting) {
            Saml2Setting::IDP_ENTITY_ID                                                              => self::entityId($value),
            Saml2Setting::SSO_URL, Saml2Setting::IDP_INITIATED_START_URL, Saml2Setting::METADATA_URL => SettingRules::url($value),
            Saml2Setting::SSO_BINDING, Saml2Setting::SUBJECT_SOURCE, Saml2Setting::NAME_ID_FORMAT    => SettingRules::choice($value, self::CHOICES[$setting->value]),
            Saml2Setting::SUBJECT_ATTRIBUTE                                                          => $this->subjectAttribute($value),
            Saml2Setting::MAX_AUTHENTICATION_AGE_SECONDS                                             => self::authenticationAge($value),
            Saml2Setting::REQUIRE_ENCRYPTED_ASSERTIONS, Saml2Setting::IDP_INITIATED                  => self::gated($value, self::GATES[$setting->value]),
            default                                                                                  => SettingRules::boolean($value),
        };
    }

    /**
     * What another setting requires of one not given: the subject attribute
     * when the subject comes from an attribute, the start URL when
     * IdP-initiated sign-in is on, and the metadata URL when metadata
     * refreshes.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting  $setting
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    private function requirement(Saml2Setting $setting): ?ViolationCode
    {
        $required = match ($setting) {
            Saml2Setting::SUBJECT_ATTRIBUTE       => ($this->values[Saml2Setting::SUBJECT_SOURCE->value] ?? null)   === 'attribute',
            Saml2Setting::IDP_INITIATED_START_URL => ($this->values[Saml2Setting::IDP_INITIATED->value] ?? null)    === true,
            Saml2Setting::METADATA_URL            => ($this->values[Saml2Setting::METADATA_REFRESH->value] ?? null) === true,
            default                               => false,
        };

        return $required ? ViolationCode::REQUIRED : null;
    }

    /**
     * The subject attribute: a name of at most 1024 bytes, given only when the
     * subject comes from an attribute.
     *
     * @param  mixed  $value
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    private function subjectAttribute(mixed $value): ?ViolationCode
    {
        $code = SettingRules::text($value, self::MAX_VALUE_LENGTH);

        if ($code !== null) {
            return $code;
        }

        $source = $this->values[Saml2Setting::SUBJECT_SOURCE->value] ?? self::DEFAULTS[Saml2Setting::SUBJECT_SOURCE->value];

        return $source === 'name_id' ? ViolationCode::UNSUPPORTED : null;
    }

    /**
     * The identity provider's entity id: an `http:` or `https:` URL with a
     * host, or a URN, of at most 1024 bytes with no whitespace.
     *
     * @param  mixed  $value
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    private static function entityId(mixed $value): ?ViolationCode
    {
        $code = SettingRules::text($value, self::MAX_VALUE_LENGTH, false);

        if ($code !== null || !is_string($value)) {
            return $code;
        }

        if (preg_match(self::HTTP_URI, $value) === 1) {
            $host = parse_url($value, PHP_URL_HOST);

            return is_string($host) && $host !== '' ? null : ViolationCode::INVALID_FORMAT;
        }

        return preg_match(self::URN, $value) === 1 ? null : ViolationCode::INVALID_FORMAT;
    }

    /**
     * The maximum authentication age: an integer from 60 seconds to a week.
     *
     * @param  mixed  $value
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     */
    private static function authenticationAge(mixed $value): ?ViolationCode
    {
        if (!is_int($value)) {
            return ViolationCode::INVALID_TYPE;
        }

        return $value < self::MIN_AUTHENTICATION_AGE_SECONDS || $value > self::MAX_AUTHENTICATION_AGE_SECONDS ? ViolationCode::NOT_ALLOWED : null;
    }

    /**
     * A switch that may be on only while its feature is.
     *
     * @param  mixed  $value
     * @param  \SineMacula\Laravel\Sso\Config\Enums\Feature  $feature
     * @return ?\SineMacula\Laravel\Sso\Connections\Enums\ViolationCode
     *
     * @throws \InvalidArgumentException
     */
    private static function gated(mixed $value, Feature $feature): ?ViolationCode
    {
        $code = SettingRules::boolean($value);

        if ($code !== null) {
            return $code;
        }

        return $value === true && !Features::enabled($feature) ? ViolationCode::UNSUPPORTED : null;
    }

    /**
     * The encryption algorithms: a non-empty list from the allow-list, with at
     * least one key transport and one data encryption algorithm.
     *
     * @param  string  $name
     * @param  mixed  $value
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    private static function encryptionAlgorithms(string $name, mixed $value): array
    {
        $data       = [...self::DATA_ENCRYPTION_ALGORITHMS, ...self::CBC_ALGORITHMS];
        $violations = SettingRules::allowedList($name, $value, [...self::KEY_TRANSPORT_ALGORITHMS, ...$data]);

        if ($violations !== [] || !is_array($value)) {
            return $violations;
        }

        $complete = array_intersect($value, self::KEY_TRANSPORT_ALGORITHMS) !== [] && array_intersect($value, $data) !== [];

        return $complete ? [] : SettingRules::at($name, ViolationCode::REQUIRED);
    }

    /**
     * The authentication context classes: a list of at most ten, each of at
     * most 1024 bytes with no whitespace.
     *
     * @param  string  $name
     * @param  mixed  $value
     * @return list<\SineMacula\Laravel\Sso\Connections\SettingViolation>
     */
    private static function authnContexts(string $name, mixed $value): array
    {
        $code = SettingRules::list($value);

        if ($code !== null || !is_array($value)) {
            return SettingRules::at($name, $code ?? ViolationCode::INVALID_TYPE);
        }

        if (count($value) > self::MAX_AUTHN_CONTEXTS) {
            return SettingRules::at($name, ViolationCode::TOO_MANY);
        }

        $violations = [];

        foreach ($value as $index => $context) {
            array_push($violations, ...SettingRules::at($name . '.' . $index, SettingRules::text($context, self::MAX_VALUE_LENGTH, false)));
        }

        return $violations;
    }
}
