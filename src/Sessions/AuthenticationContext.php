<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Sessions;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Sessions\Enums\ContextKey;

/**
 * Projects a session's provenance into plain values under `ContextKey`; an
 * absent key means no SSO provenance, a `null` a fact not stated.
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
            ContextKey::CONNECTION->value                       => $provenance->connectionId,
            ContextKey::TENANT->value                           => $provenance->tenantId,
            ContextKey::PROTOCOL->value                         => $provenance->protocol,
            ContextKey::PROVIDER_AUTH_TIME->value               => self::instant($provenance->providerAuthenticatedAt),
            ContextKey::PROVIDER_AMR->value                     => $provenance->providerMethods(),
            ContextKey::PROVIDER_ACR->value                     => $provenance->providerAcr(),
            ContextKey::PROVIDER_AUTHN_CONTEXT_CLASS_REF->value => $provenance->providerAuthnContextClassRef(),
            ContextKey::LINK->value                             => $provenance->linkId,
            ContextKey::LINK_PROVENANCE->value                  => $provenance->linkProvenance?->value,
            ContextKey::PROVIDER_SESSION_DEADLINE->value        => self::instant($provenance->providerSessionDeadline),
            ContextKey::SESSION_NOT_AFTER->value                => self::instant($provenance->sessionNotAfter),
            ContextKey::ENFORCEMENT_VERSION->value              => $provenance->enforcementVersion,
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
