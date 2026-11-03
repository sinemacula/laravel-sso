<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Sessions;

use Carbon\CarbonImmutable;

/**
 * The package's contribution to the authentication context of a request
 * (SSO-9.7): a pure projection of a session's stored provenance
 * (`Sessions\Provenance`, SSO-9.10) into the keys of the `sso` namespace, so a
 * policy can require "signed in through SSO" without depending on this package.
 * It reads only the provenance it is given, never the current connection, link
 * or evidence policy, and keeps nothing between calls.
 *
 * A session with no provenance from this package contributes nothing: `[]`,
 * with no `sso.*` key at all. A session with provenance contributes every key,
 * `null` where the fact was not stated, so a key that is absent means "not
 * established through this package" and a `null` means "established through it,
 * without that fact". Every value is plain: a string, a list of strings or
 * `null`, never an object or a type of this package, so the projection can be
 * handed as it is to anything that holds only plain values:
 *
 * - `sso.connection`: the connection's opaque id, a string;
 * - `sso.tenant`: the connection's tenant at sign-in, a string, never the
 *   session's current active tenant;
 * - `sso.protocol`: the registered driver's name, a string (`saml2`, `oidc` or
 *   an application's own driver);
 * - `sso.provider_auth_time`: when the provider authenticated the person, a
 *   UTC instant to the microsecond as asserted, or `null`;
 * - `sso.provider_amr`: the RFC 8176 methods the evidence contract accepted at
 *   sign-in, a list of strings, `[]` when it accepted none;
 * - `sso.provider_acr`: the raw `acr` the accepted evidence carried, for any
 *   driver but `saml2` (OIDC and an application's own), a string or `null`;
 *   data, never an assurance level;
 * - `sso.provider_authn_context_class_ref`: the raw SAML `AuthnContextClassRef`
 *   the accepted evidence carried, for the `saml2` driver, a string or `null`;
 *   data, never an assurance level;
 * - `sso.link`: the exact link admitted, an opaque string, or `null` for an
 *   unlinked admission;
 * - `sso.link_provenance`: that link's provenance as admitted, the backed value
 *   of `Links\Enums\LinkOrigin` (`link_purpose`, `provisioning`,
 *   `verified_domain`, `migration`), or `null` with no link or when the linker
 *   did not state it;
 * - `sso.provider_session_deadline`: the provider's raw session deadline, a
 *   UTC instant to the microsecond or `null`;
 * - `sso.session_not_after`: the effective cap that deadline set on the
 *   application's session, a UTC instant to the second, or `null` when none
 *   was set (the deadline contract ignored it, or there was none);
 * - `sso.enforcement_version`: the version of the enforcement the sign-in's
 *   redemption judged under its locks, an opaque string, or `null`.
 *
 * Each instant is a string in `Provenance::INSTANT_FORMAT`
 * (`Y-m-d\TH:i:s.u\Z`), the form the stored provenance keeps it in: UTC, its
 * microseconds kept exactly, so `of()` of a provenance and `fromStored()` of
 * its `toArray()` answer identical arrays. `Provenance` itself keeps its times
 * as `CarbonImmutable` instants for a caller in PHP.
 *
 * It never contributes the subject, the issuer, the provider session's id, an
 * email, groups, a mapped attribute or a token. The keys, their meanings and
 * their types are stable from 1.0.0. They are historical: how the session
 * began. They never stand in for a current check of revocation, enforcement or
 * freshness, and a re-authentication or a later confirming `link` never changes
 * them.
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

    /** @var string The connection's tenant at sign-in. */
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

    /** @var string The version of the enforcement the sign-in's redemption judged under its locks. */
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
     * The `sso.*` keys of the provenance a session stored in its
     * `Provenance::toArray()` form; none for a session that stored none
     * (`null`). A stored form this version did not write is an
     * `UnexpectedValueException`, never an empty contribution.
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
     * The instant, which the provenance holds in UTC, as its stored form keeps
     * it: a string to the microsecond, or `null` for none.
     *
     * @param  ?\Carbon\CarbonImmutable  $instant
     * @return ?string
     */
    private static function instant(?CarbonImmutable $instant): ?string
    {
        return $instant?->format(Provenance::INSTANT_FORMAT);
    }
}
