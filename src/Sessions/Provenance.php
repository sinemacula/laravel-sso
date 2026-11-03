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
 * How a session established through this package began (SSO-9.7, SSO-9.10): an
 * immutable record captured once, inside the transaction of a successful
 * `sign_in` redemption, from what that redemption admitted, and never rebuilt
 * from today's connection, link or evidence policy.
 *
 * It holds the connection and the tenant it belonged to at sign-in; the
 * connection's protocol (the registered driver's name); when the provider
 * authenticated the person; the RFC 8176 `amr` values the evidence contract
 * accepted at redemption (none when it accepted nothing), and the raw context
 * class that accepted evidence carried, as SAML `AuthnContextClassRef` for the
 * package's `saml2` driver and as `acr` for every other driver, `oidc` and an
 * application's own alike, as the evidence policy reads them; the exact link
 * admitted and its provenance as it stood under the redemption's locks; the
 * provider's raw session deadline (`SessionNotOnOrAfter`), and the effective
 * cap it set on the application's session, which is `null` when the provider
 * session deadline contract ignored it; and the version of the enforcement the
 * redemption judged under its locks. Never the subject, the issuer, the
 * provider session's id, an email, groups, any mapped attribute or any token.
 *
 * `capture()` builds it from an admitted `sign_in` only: a `link` or a
 * `reauthenticate` redemption, a refused admission, and anything outside the
 * caller's transaction capture nothing, so a re-authentication or a later
 * confirming `link` never yields a value that could overwrite how a session
 * began. `Handoffs\HandoffRedemption` captures it and answers it on the
 * redemption result for the adapter to write with the session, once.
 *
 * Each part keeps to the domain a capture can produce, so the stored form stays
 * small whatever it holds: the connection id, the link id and the enforcement
 * version are printable ASCII, the tenant id valid UTF-8 (it is the
 * application's own opaque id), the protocol a registered driver's name, the
 * methods RFC 8176's registered values, each at most once, and the raw context
 * class printable ASCII of at most `MAX_CONTEXT_LENGTH` bytes. With every part
 * at its limit and every character one that JSON escapes, the stored form
 * encoded as JSON (`json_encode()` with its default escaping) takes 3,364
 * bytes, under `MAX_STORED_JSON_BYTES` (`ProvenanceDomain` holds the rules).
 * `capture()` keeps a raw context class outside that domain as `null`, and
 * keeps only the registered methods of the accepted evidence, so neither ever
 * fails a sign-in.
 *
 * `toArray()` is the stored form, versioned (`version` is `1`), with every key
 * present and `null` where a fact was not stated; instants are UTC strings to
 * the microsecond (`Y-m-d\TH:i:s.u\Z`) and the link's provenance is its enum
 * value. `restore()` reads exactly that form back, refusing any other version,
 * a missing or unknown key, or a malformed value with an
 * `UnexpectedValueException`. `json_encode()` and a dump show the methods only
 * as a count and the raw context only as `[redacted]`, so their output is not
 * the stored form; PHP serialisation is refused, since only the versioned array
 * is a stable form.
 *
 * These are historical facts. They never stand in for a current check of
 * revocation, enforcement or freshness.
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

    /** @var string The one driver whose raw context class is SAML `AuthnContextClassRef`; every other's is `acr`. */
    public const string SAML2 = Saml2Driver::NAME;

    /** @var int The longest tenant id or link id, in bytes. */
    public const int MAX_ID_LENGTH = 255;

    /** @var int The longest connection id, in bytes: the package's own are 26-character ULIDs. */
    public const int MAX_CONNECTION_ID_LENGTH = 64;

    /** @var int The longest enforcement version, in bytes. */
    public const int MAX_VERSION_LENGTH = 64;

    /** @var int The longest raw `acr` or `AuthnContextClassRef` kept, in bytes. */
    public const int MAX_CONTEXT_LENGTH = 255;

    /** @var int The most bytes the stored form takes as JSON with the default escaping, whatever it holds. */
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

        // When the provider authenticated the person; kept in UTC
        ?CarbonImmutable $providerAuthenticatedAt = null,

        // The accepted RFC 8176 `amr` values; held wrapped
        #[\SensitiveParameter]
        array $methods = [],

        // The accepted raw `acr`, of any driver but `saml2`; held wrapped
        #[\SensitiveParameter]
        ?string $acr = null,

        // The accepted raw SAML `AuthnContextClassRef`; held wrapped
        #[\SensitiveParameter]
        ?string $authnContextClassRef = null,

        /** The exact link admitted; `null` for an unlinked admission. */
        public ?string $linkId = null,

        /** The admitted link's provenance as it stood under the redemption's locks. */
        public ?LinkOrigin $linkProvenance = null,

        // The provider's raw session deadline; kept in UTC
        ?CarbonImmutable $providerSessionDeadline = null,

        // The effective cap on the application's session; kept in UTC
        ?CarbonImmutable $sessionNotAfter = null,

        /** The version of the enforcement the redemption judged under its locks. */
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
     * What a dump shows: what `json_encode()` writes.
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
     * Capture the provenance of the admitted `sign_in`: from the verified
     * result its code carried, what the admission established under the locks
     * (the evidence accepted, the link and its provenance, the version of the
     * enforcement judged), and the effective session cap the code was bound to.
     * `null` for any other purpose, or an admission that did not pass. Only the
     * registered RFC 8176 methods of the accepted evidence are kept, each once,
     * and a raw context class that is not printable ASCII of at most
     * `MAX_CONTEXT_LENGTH` bytes is kept as `null`: both are data, never a
     * decision, so neither fails a sign-in.
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
     * The provenance `toArray()` stored, read back from the adapter's storage;
     * never from client input.
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
     * The stored form: versioned, with every key, `null` where a fact was not
     * stated, instants in UTC to the microsecond and the link's provenance as
     * its enum value.
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
     * The raw `acr` the accepted evidence carried, of any driver but `saml2`,
     * as data and never an assurance level.
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
     * The raw SAML `AuthnContextClassRef` the accepted evidence carried, as
     * data and never an assurance level.
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
     * What `json_encode()` writes: the stored form with the methods as a count
     * and each raw context as `[redacted]` when stated; not a stored form.
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
     * Refuse both raw contexts stated at once, since a session has one
     * protocol, and a link provenance with no link.
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
     * The link provenance a stored value names by its enum value, or `null` for
     * `null`.
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
     * The instant a stored value names, in its exact stored form, or `null` for
     * `null`.
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
     * What the JSON shows of a raw context: `[redacted]` when stated, `null`
     * when not.
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
