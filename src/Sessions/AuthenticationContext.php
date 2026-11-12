<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Sessions;

use Carbon\CarbonImmutable;

/**
 * Projects a session's provenance into plain `sso.*` values; an absent key
 * means no SSO provenance, a `null` a fact not stated.
 *
 * The keys are historical and stable from 1.0.0; they never replace a current
 * revocation, enforcement or freshness check.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AuthenticationContext
{
    /** @var string The namespace the package owns in the authentication context. */
    public const string NAMESPACE = 'sso';

    /** @var string The connection's opaque id. */
    public const string CONNECTION = 'sso.connection';

    /** @var string The connection's tenant at sign-in, not the active tenant. */
    public const string TENANT = 'sso.tenant';

    /** @var string The registered driver's name. */
    public const string PROTOCOL = 'sso.protocol';

    /** @var string When the provider authenticated the person. */
    public const string PROVIDER_AUTH_TIME = 'sso.provider_auth_time';

    /** @var string The accepted RFC 8176 methods. */
    public const string PROVIDER_AMR = 'sso.provider_amr';

    /** @var string The accepted raw `acr`, of any driver but `saml2`. */
    public const string PROVIDER_ACR = 'sso.provider_acr';

    /** @var string The accepted raw SAML `AuthnContextClassRef`. */
    public const string PROVIDER_AUTHN_CONTEXT_CLASS_REF = 'sso.provider_authn_context_class_ref';

    /** @var string The exact link admitted. */
    public const string LINK = 'sso.link';

    /** @var string The admitted link's provenance. */
    public const string LINK_PROVENANCE = 'sso.link_provenance';

    /** @var string The provider's raw session deadline. */
    public const string PROVIDER_SESSION_DEADLINE = 'sso.provider_session_deadline';

    /** @var string The effective cap on the application's session. */
    public const string SESSION_NOT_AFTER = 'sso.session_not_after';

    /** @var string The enforcement version the sign-in's redemption judged. */
    public const string ENFORCEMENT_VERSION = 'sso.enforcement_version';

    /** @var list<string> Every key a session with provenance contributes, in order. */
    public const array KEYS = [
        self::CONNECTION,
        self::TENANT,
        self::PROTOCOL,
        self::PROVIDER_AUTH_TIME,
        self::PROVIDER_AMR,
        self::PROVIDER_ACR,
        self::PROVIDER_AUTHN_CONTEXT_CLASS_REF,
        self::LINK,
        self::LINK_PROVENANCE,
        self::PROVIDER_SESSION_DEADLINE,
        self::SESSION_NOT_AFTER,
        self::ENFORCEMENT_VERSION,
    ];

    /**
     * Disallow instantiation; a pure projection only.
     */
    private function __construct() {}

    /**
     * The `sso.*` keys of the provenance; none for none.
     *
     * @param  ?\SineMacula\Laravel\Sso\Sessions\Provenance  $provenance
     * @return array<string, list<string>|string|null>
     */
    public static function of(?Provenance $provenance): array
    {
        if ($provenance === null) {
            return [];
        }

        return [
            self::CONNECTION                       => $provenance->connectionId,
            self::TENANT                           => $provenance->tenantId,
            self::PROTOCOL                         => $provenance->protocol,
            self::PROVIDER_AUTH_TIME               => self::instant($provenance->providerAuthenticatedAt),
            self::PROVIDER_AMR                     => $provenance->providerMethods(),
            self::PROVIDER_ACR                     => $provenance->providerAcr(),
            self::PROVIDER_AUTHN_CONTEXT_CLASS_REF => $provenance->providerAuthnContextClassRef(),
            self::LINK                             => $provenance->linkId,
            self::LINK_PROVENANCE                  => $provenance->linkProvenance?->value,
            self::PROVIDER_SESSION_DEADLINE        => self::instant($provenance->providerSessionDeadline),
            self::SESSION_NOT_AFTER                => self::instant($provenance->sessionNotAfter),
            self::ENFORCEMENT_VERSION              => $provenance->enforcementVersion,
        ];
    }

    /**
     * The `sso.*` keys of a stored `Provenance::toArray()`; none for `null`.
     *
     * @param  ?array<array-key, mixed>  $stored
     * @return array<string, list<string>|string|null>
     *
     * @throws \UnexpectedValueException
     */
    public static function fromStored(?array $stored): array
    {
        return self::of($stored === null ? null : Provenance::restore($stored));
    }

    /**
     * The UTC instant in the stored form, so `of()` and `fromStored()` agree.
     *
     * @param  ?\Carbon\CarbonImmutable  $instant
     * @return ?string
     */
    private static function instant(?CarbonImmutable $instant): ?string
    {
        return $instant?->format(Provenance::INSTANT_FORMAT);
    }
}
