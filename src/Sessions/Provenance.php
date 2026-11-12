<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Sessions;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\Redemption\Admission;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * How a session began, captured once at a `sign_in` redemption and never
 * rebuilt from current state.
 *
 * Historical facts only; they never replace a current revocation, enforcement
 * or freshness check.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Provenance implements \JsonSerializable
{
    /** @var int The version of the stored form `toArray()` writes. */
    public const int VERSION = 1;

    /** @var string The driver whose raw context is `AuthnContextClassRef`, not `acr`. */
    public const string SAML2 = Saml2Driver::NAME;

    /** @var int The longest tenant id or link id, in bytes. */
    public const int MAX_ID_LENGTH = 255;

    /** @var int The longest connection id, in bytes. */
    public const int MAX_CONNECTION_ID_LENGTH = 64;

    /** @var int The longest enforcement version, in bytes. */
    public const int MAX_VERSION_LENGTH = 64;

    /** @var int The longest raw `acr` or `AuthnContextClassRef` kept, in bytes. */
    public const int MAX_CONTEXT_LENGTH = 255;

    /** @var int Upper bound on the stored form as default-escaped JSON. */
    public const int MAX_STORED_JSON_BYTES = 4096;

    /** @var string The form an instant is stored in: UTC, to the microsecond. */
    public const string INSTANT_FORMAT = 'Y-m-d\TH:i:s.u\Z';

    /** @var list<string> Every key of the stored form. */
    public const array STORED_KEYS = [
        'version',
        'connection_id',
        'tenant_id',
        'protocol',
        'provider_auth_time',
        'provider_amr',
        'provider_acr',
        'provider_authn_context_class_ref',
        'link_id',
        'link_provenance',
        'provider_session_deadline',
        'session_not_after',
        'enforcement_version',
    ];

    /** @var ?\Carbon\CarbonImmutable When the provider authenticated the person, in UTC. */
    public ?CarbonImmutable $providerAuthenticatedAt;

    /** @var ?\Carbon\CarbonImmutable The provider's raw session deadline, in UTC. */
    public ?CarbonImmutable $providerSessionDeadline;

    /** @var ?\Carbon\CarbonImmutable The effective cap on the application's session, in UTC. */
    public ?CarbonImmutable $sessionNotAfter;

    /** @var \SensitiveParameterValue The accepted RFC 8176 `amr` values. */
    private \SensitiveParameterValue $methods;

    /** @var \SensitiveParameterValue The accepted raw `acr` and SAML `AuthnContextClassRef`. */
    private \SensitiveParameterValue $contexts;

    /**
     * Constructor.
     *
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @param  string  $protocol
     * @param  ?\Carbon\CarbonImmutable  $providerAuthenticatedAt
     * @param  list<string>  $methods
     * @param  ?string  $acr
     * @param  ?string  $authnContextClassRef
     * @param  ?string  $linkId
     * @param  ?\SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $linkProvenance
     * @param  ?\Carbon\CarbonImmutable  $providerSessionDeadline
     * @param  ?\Carbon\CarbonImmutable  $sessionNotAfter
     * @param  ?string  $enforcementVersion
     *
     * @throws \InvalidArgumentException
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** The connection the session was established through. */
        public string $connectionId,

        /** The connection's tenant at sign-in. */
        public string $tenantId,

        /** The connection's protocol: the registered driver's name. */
        public string $protocol,

        // Converted to UTC
        ?CarbonImmutable $providerAuthenticatedAt = null,

        // Held wrapped
        #[\SensitiveParameter]
        array $methods = [],

        // Held wrapped; any driver but `saml2`
        #[\SensitiveParameter]
        ?string $acr = null,

        // Held wrapped
        #[\SensitiveParameter]
        ?string $authnContextClassRef = null,

        /** The exact link admitted; `null` for an unlinked admission. */
        public ?string $linkId = null,

        /** The admitted link's provenance under the redemption's locks. */
        public ?LinkOrigin $linkProvenance = null,

        // Converted to UTC
        ?CarbonImmutable $providerSessionDeadline = null,

        // Converted to UTC
        ?CarbonImmutable $sessionNotAfter = null,

        /** The enforcement version the redemption judged under its locks. */
        public ?string $enforcementVersion = null,
    ) {
        ProvenanceDomain::assertText('connection id', $connectionId, self::MAX_CONNECTION_ID_LENGTH, false);
        ProvenanceDomain::assertTenant($tenantId);
        ProvenanceDomain::assertProtocol($protocol);
        ProvenanceDomain::assertText('link id', $linkId, self::MAX_ID_LENGTH, true);
        ProvenanceDomain::assertText('enforcement version', $enforcementVersion, self::MAX_VERSION_LENGTH, true);
        ProvenanceDomain::assertMethods($methods);
        ProvenanceDomain::assertText('acr', $acr, self::MAX_CONTEXT_LENGTH, true);
        ProvenanceDomain::assertText('AuthnContextClassRef', $authnContextClassRef, self::MAX_CONTEXT_LENGTH, true);
        self::assertCoherent($acr, $authnContextClassRef, $linkId, $linkProvenance);

        $this->providerAuthenticatedAt = $providerAuthenticatedAt?->utc();
        $this->providerSessionDeadline = $providerSessionDeadline?->utc();
        $this->sessionNotAfter         = $sessionNotAfter?->utc();
        $this->methods                 = new \SensitiveParameterValue($methods);
        $this->contexts                = new \SensitiveParameterValue([$acr, $authnContextClassRef]);
    }

    /**
     * A dump shows the redacted JSON form.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return $this->jsonSerialize();
    }

    /**
     * Refuse PHP serialisation: the versioned `toArray()` is the stable form.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A session provenance is stored as its toArray() form, never PHP-serialised.');
    }

    /**
     * Refuse PHP unserialisation.
     *
     * @param  array<string, mixed>  $data
     * @return void
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     * @SuppressWarnings("php:S1172")
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('A session provenance is restored from its toArray() form, never PHP-unserialised.');
    }

    /**
     * Capture a passed `sign_in` admission, else `null`; evidence outside the
     * domain is dropped rather than failing the sign-in.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  \SineMacula\Laravel\Sso\Handoffs\Redemption\Admission  $admission
     * @param  ?\Carbon\CarbonImmutable  $sessionNotAfter
     * @return ?self
     *
     * @throws \InvalidArgumentException
     */
    public static function capture(VerifiedResult $result, Admission $admission, ?CarbonImmutable $sessionNotAfter): ?self
    {
        if ($result->purpose !== Purpose::SIGN_IN || !$admission->isPassed()) {
            return null;
        }

        $evidence = $admission->evidence;
        $raw      = ProvenanceDomain::keptContext($evidence?->rawContext());
        $context  = $result->authenticationContext;

        return new self(
            $result->connectionId,
            $result->tenantId,
            $result->protocol,
            $context->authenticatedAt,
            ProvenanceDomain::registered($evidence?->methods() ?? []),
            $result->protocol === self::SAML2 ? null : $raw,
            $result->protocol === self::SAML2 ? $raw : null,
            $admission->linkId,
            $admission->linkProvenance,
            $context->providerSessionDeadline,
            $sessionNotAfter,
            $admission->enforcementVersion,
        );
    }

    /**
     * Restore `toArray()` output from adapter storage, never client input.
     *
     * @param  array<array-key, mixed>  $stored
     * @return self
     *
     * @throws \UnexpectedValueException
     */
    public static function restore(array $stored): self
    {
        $keys     = array_keys($stored);
        $expected = self::STORED_KEYS;

        sort($keys);
        sort($expected);

        if ($keys !== $expected || $stored['version'] !== self::VERSION) {
            throw self::corrupt();
        }

        try {
            return new self(
                (string) self::text($stored, 'connection_id', false),
                (string) self::text($stored, 'tenant_id', false),
                (string) self::text($stored, 'protocol', false),
                self::instant($stored['provider_auth_time']),
                is_array($stored['provider_amr']) ? $stored['provider_amr'] : throw self::corrupt(), // @phpstan-ignore argument.type
                self::text($stored, 'provider_acr', true),
                self::text($stored, 'provider_authn_context_class_ref', true),
                self::text($stored, 'link_id', true),
                self::origin($stored['link_provenance']),
                self::instant($stored['provider_session_deadline']),
                self::instant($stored['session_not_after']),
                self::text($stored, 'enforcement_version', true),
            );
        } catch (\InvalidArgumentException) {
            throw self::corrupt();
        }
    }

    /**
     * The versioned stored form, with every key present.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'version'                          => self::VERSION,
            'connection_id'                    => $this->connectionId,
            'tenant_id'                        => $this->tenantId,
            'protocol'                         => $this->protocol,
            'provider_auth_time'               => $this->providerAuthenticatedAt?->format(self::INSTANT_FORMAT),
            'provider_amr'                     => $this->providerMethods(),
            'provider_acr'                     => $this->providerAcr(),
            'provider_authn_context_class_ref' => $this->providerAuthnContextClassRef(),
            'link_id'                          => $this->linkId,
            'link_provenance'                  => $this->linkProvenance?->value,
            'provider_session_deadline'        => $this->providerSessionDeadline?->format(self::INSTANT_FORMAT),
            'session_not_after'                => $this->sessionNotAfter?->format(self::INSTANT_FORMAT),
            'enforcement_version'              => $this->enforcementVersion,
        ];
    }

    /**
     * The accepted RFC 8176 `amr` values; none when nothing was accepted.
     *
     * @return list<string>
     */
    public function providerMethods(): array
    {
        /** @var list<string> */
        return $this->methods->getValue();
    }

    /**
     * The raw `acr` accepted, as data, never an assurance level.
     *
     * @return ?string
     */
    public function providerAcr(): ?string
    {
        /** @var array{0: ?string, 1: ?string} $contexts */
        $contexts = $this->contexts->getValue();

        return $contexts[0];
    }

    /**
     * The raw `AuthnContextClassRef` accepted, as data, not an assurance level.
     *
     * @return ?string
     */
    public function providerAuthnContextClassRef(): ?string
    {
        /** @var array{0: ?string, 1: ?string} $contexts */
        $contexts = $this->contexts->getValue();

        return $contexts[1];
    }

    /**
     * The stored form with methods counted and raw contexts redacted.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return array_replace($this->toArray(), [
            'provider_amr'                     => count($this->providerMethods()),
            'provider_acr'                     => self::redacted($this->providerAcr()),
            'provider_authn_context_class_ref' => self::redacted($this->providerAuthnContextClassRef()),
        ]);
    }

    /**
     * Refuse both raw contexts at once, or a link provenance with no link.
     *
     * @param  ?string  $acr
     * @param  ?string  $authnContextClassRef
     * @param  ?string  $linkId
     * @param  ?\SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $linkProvenance
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertCoherent(
        #[\SensitiveParameter] ?string $acr,
        #[\SensitiveParameter] ?string $authnContextClassRef,
        ?string $linkId,
        ?LinkOrigin $linkProvenance,
    ): void {
        if ($acr !== null && $authnContextClassRef !== null) {
            throw new \InvalidArgumentException('A session provenance states an acr or an AuthnContextClassRef, never both.');
        }

        if ($linkProvenance !== null && $linkId === null) {
            throw new \InvalidArgumentException('A session provenance states a link provenance only with its link.');
        }
    }

    /**
     * The stored string under the key, or `null` where that is allowed.
     *
     * @param  array<array-key, mixed>  $stored
     * @param  string  $key
     * @param  bool  $optional
     * @return ?string
     *
     * @throws \UnexpectedValueException
     */
    private static function text(array $stored, string $key, bool $optional): ?string
    {
        $value = $stored[$key];

        if (is_string($value) || ($optional && $value === null)) {
            return $value;
        }

        throw self::corrupt();
    }

    /**
     * The link provenance a stored enum value names.
     *
     * @param  mixed  $value
     * @return ?\SineMacula\Laravel\Sso\Links\Enums\LinkOrigin
     *
     * @throws \UnexpectedValueException
     */
    private static function origin(mixed $value): ?LinkOrigin
    {
        if ($value === null) {
            return null;
        }

        return (is_string($value) ? LinkOrigin::tryFrom($value) : null) ?? throw self::corrupt();
    }

    /**
     * The instant a stored value names in its exact stored form.
     *
     * @param  mixed  $value
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \UnexpectedValueException
     */
    private static function instant(mixed $value): ?CarbonImmutable
    {
        if ($value === null) {
            return null;
        }

        try {
            $instant = is_string($value) ? CarbonImmutable::createFromFormat(self::INSTANT_FORMAT, $value, 'UTC') : null;
        } catch (\InvalidArgumentException) {
            $instant = null;
        }

        if ($instant instanceof CarbonImmutable && $instant->format(self::INSTANT_FORMAT) === $value) {
            return $instant;
        }

        throw self::corrupt();
    }

    /**
     * `[redacted]` for a stated value, `null` for none.
     *
     * @param  ?string  $value
     * @return ?string
     */
    private static function redacted(#[\SensitiveParameter] ?string $value): ?string
    {
        return $value === null ? null : '[redacted]';
    }

    /**
     * The exception for a stored form that is not one this version wrote.
     *
     * @return \UnexpectedValueException
     */
    private static function corrupt(): \UnexpectedValueException
    {
        return new \UnexpectedValueException('A stored session provenance is not one this version of the package wrote.');
    }
}
