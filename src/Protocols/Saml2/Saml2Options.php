<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2;

use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;

/**
 * A SAML connection's settings, typed, for the driver and its collaborators to
 * read (SSO-2.3): every setting of `Saml2Settings`, defaults applied, under a
 * property of its own. It is read from what the connection holds at the moment
 * it is built, which the driver does once per call, so nothing is kept between
 * calls (SSO-11.2).
 *
 * Only a complete connection is ever used (`Saml2Driver::isComplete()`), so a
 * flow reads a valid entity id and single sign-on URL; a setting the connection
 * does not hold is `null` (or its default). It holds no secret: a SAML
 * connection's keys and trusted certificates are kept with its keys.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Saml2Options
{
    /** @var array<string, string> The URI of each NameID format a connection may name. */
    public const array NAME_ID_FORMATS = [
        'persistent'  => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
        'email'       => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        'unspecified' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    ];

    /** @var string The NameID format a subject never has. */
    public const string TRANSIENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';

    /** @var array<string, string> The binding URI of each binding an `AuthnRequest` may be sent by. */
    public const array BINDINGS = [
        'http_redirect' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        'http_post'     => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    ];

    /** @var list<\SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting> The settings that are switches. */
    private const array SWITCHES = [
        Saml2Setting::SIGN_AUTHN_REQUESTS,
        Saml2Setting::WANT_ASSERTIONS_SIGNED,
        Saml2Setting::REQUIRE_ENCRYPTED_ASSERTIONS,
        Saml2Setting::FORCE_AUTHN,
        Saml2Setting::IDP_INITIATED,
        Saml2Setting::METADATA_REFRESH,
    ];

    /**
     * Constructor.
     *
     * @param  ?string  $idpEntityId
     * @param  ?string  $ssoUrl
     * @param  string  $ssoBinding
     * @param  string  $subjectSource
     * @param  ?string  $subjectAttribute
     * @param  string  $nameIdFormat
     * @param  array<string, bool>  $switches
     * @param  array<string, list<string>>  $lists
     * @param  ?int  $maxAuthenticationAgeSeconds
     * @param  ?string  $idpInitiatedStartUrl
     * @param  ?string  $metadataUrl
     */
    public function __construct(

        /** The identity provider's entity id, the `Issuer` every response and assertion must carry. */
        public ?string $idpEntityId,

        /** Its single sign-on URL. */
        public ?string $ssoUrl,

        /** The binding the `AuthnRequest` is sent by: `http_redirect` or `http_post`. */
        public string $ssoBinding,

        /** Where the subject comes from: `name_id` or `attribute`. */
        public string $subjectSource,

        /** The attribute holding a stable identifier, for an attribute subject. */
        public ?string $subjectAttribute,

        /** The NameID format requested and accepted: `persistent`, `email` or `unspecified`. */
        public string $nameIdFormat,

        /** Each switch by its setting's name: `sign_authn_requests`, `want_assertions_signed`, `require_encrypted_assertions`, `force_authn`, `idp_initiated` and `metadata_refresh`. */
        private array $switches,

        /** Each list by its setting's name: `signature_algorithms`, `encryption_algorithms` and `requested_authn_context`. */
        private array $lists,

        /** The oldest the provider's `AuthnInstant` may be, in seconds, or `null` for no limit. */
        public ?int $maxAuthenticationAgeSeconds,

        /** The application start URL an unsolicited response is sent to. */
        public ?string $idpInitiatedStartUrl,

        /** The URL the provider's metadata is refreshed from. */
        public ?string $metadataUrl,
    ) {}

    /**
     * The options the connection holds now, defaults applied.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @return self
     */
    public static function of(SsoConnection $connection): self
    {
        $values = Saml2Settings::fromArray($connection->getSettings())->toArray();
        $string = static fn (Saml2Setting $setting): ?string => is_string($values[$setting->value] ?? null) ? $values[$setting->value] : null;
        $age    = $values[Saml2Setting::MAX_AUTHENTICATION_AGE_SECONDS->value] ?? null;

        return new self(
            $string(Saml2Setting::IDP_ENTITY_ID),
            $string(Saml2Setting::SSO_URL),
            $string(Saml2Setting::SSO_BINDING)    ?? 'http_redirect',
            $string(Saml2Setting::SUBJECT_SOURCE) ?? 'name_id',
            $string(Saml2Setting::SUBJECT_ATTRIBUTE),
            $string(Saml2Setting::NAME_ID_FORMAT) ?? 'persistent',
            self::switches($values),
            self::lists($values),
            is_int($age) ? $age : null,
            $string(Saml2Setting::IDP_INITIATED_START_URL),
            $string(Saml2Setting::METADATA_URL),
        );
    }

    /**
     * Whether the switch named by the setting is on.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting  $setting
     * @return bool
     */
    public function isOn(Saml2Setting $setting): bool
    {
        return ($this->switches[$setting->value] ?? false) === true;
    }

    /**
     * The list named by the setting, in the order it was given.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting  $setting
     * @return list<string>
     */
    public function listOf(Saml2Setting $setting): array
    {
        return $this->lists[$setting->value] ?? [];
    }

    /**
     * The URI of the NameID format requested and accepted.
     *
     * @return string
     */
    public function nameIdFormatUri(): string
    {
        return self::NAME_ID_FORMATS[$this->nameIdFormat] ?? self::NAME_ID_FORMATS['persistent'];
    }

    /**
     * The URI of the binding the `AuthnRequest` is sent by.
     *
     * @return string
     */
    public function ssoBindingUri(): string
    {
        return self::BINDINGS[$this->ssoBinding] ?? self::BINDINGS['http_redirect'];
    }

    /**
     * The key transport algorithms the connection allows.
     *
     * @return list<string>
     */
    public function keyTransportAlgorithms(): array
    {
        return array_values(array_intersect($this->listOf(Saml2Setting::ENCRYPTION_ALGORITHMS), Saml2Settings::KEY_TRANSPORT_ALGORITHMS));
    }

    /**
     * The data encryption algorithms the connection allows, AES-CBC among them
     * only when it lists one.
     *
     * @return list<string>
     */
    public function dataEncryptionAlgorithms(): array
    {
        return array_values(array_intersect($this->listOf(Saml2Setting::ENCRYPTION_ALGORITHMS), [...Saml2Settings::DATA_ENCRYPTION_ALGORITHMS, ...Saml2Settings::CBC_ALGORITHMS]));
    }

    /**
     * Each switch the settings hold, by name.
     *
     * @param  array<string, mixed>  $values
     * @return array<string, bool>
     */
    private static function switches(array $values): array
    {
        $switches = [];

        foreach (self::SWITCHES as $setting) {
            $switches[$setting->value] = ($values[$setting->value] ?? false) === true;
        }

        return $switches;
    }

    /**
     * Each list the settings hold, by name, with only its strings.
     *
     * @param  array<string, mixed>  $values
     * @return array<string, list<string>>
     */
    private static function lists(array $values): array
    {
        $lists = [];

        foreach ([Saml2Setting::SIGNATURE_ALGORITHMS, Saml2Setting::ENCRYPTION_ALGORITHMS, Saml2Setting::REQUESTED_AUTHN_CONTEXT] as $setting) {
            $list = $values[$setting->value] ?? [];

            $lists[$setting->value] = is_array($list) ? array_values(array_filter($list, is_string(...))) : [];
        }

        return $lists;
    }
}
