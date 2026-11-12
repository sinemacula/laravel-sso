<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Revocation;

use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind;

/**
 * Which sessions to revoke and why, built through its named constructors.
 *
 * It holds no secret, so an adapter may log it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RevocationScope
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind  $kind
     * @param  \SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason  $reason
     * @param  string  $tenantId
     * @param  ?string  $connectionId
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?\SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
     * @param  ?string  $linkId
     */
    private function __construct(

        /** Which sessions the call concerns. */
        public RevocationScopeKind $kind,

        /** Why they are revoked. */
        public RevocationReason $reason,

        /** The tenant: the enforcing tenant, or the connection's. */
        public string $tenantId,

        /** The sessions' connection, for the connection and identity scopes. */
        public ?string $connectionId = null,

        /** The identity whose sessions are revoked, for the identity scopes. */
        public ?IdentityReference $identity = null,

        /** The enforcement now in force, for the tenant scope. */
        public ?EnforcementPolicy $policy = null,

        /** The sessions' link, for the identity scopes. */
        public ?string $linkId = null,
    ) {}

    /**
     * The sessions the tenant's current enforcement no longer allows.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
     * @return self
     */
    public static function tenant(EnforcementPolicy $policy): self
    {
        return new self(RevocationScopeKind::TENANT, RevocationReason::ENFORCEMENT_CHANGED, $policy->enforcingTenantId, policy: $policy);
    }

    /**
     * Every session established through the connection, disabled or deleted.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason  $reason
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function connection(string $tenantId, string $connectionId, RevocationReason $reason): self
    {
        if ($reason !== RevocationReason::CONNECTION_DISABLED && $reason !== RevocationReason::CONNECTION_DELETED) {
            throw new \InvalidArgumentException(sprintf('A connection\'s sessions are not revoked for [%s].', $reason->value));
        }

        self::assertIds($tenantId, $connectionId);

        return new self(RevocationScopeKind::CONNECTION, $reason, $tenantId, $connectionId);
    }

    /**
     * The identity's sessions through a removed link; an adapter that does not
     * record links may revoke by connection.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $linkId
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function identityInConnection(string $tenantId, string $connectionId, IdentityReference $identity, string $linkId): self
    {
        self::assertIds($tenantId, $connectionId, $linkId);

        return new self(RevocationScopeKind::IDENTITY_CONNECTION, RevocationReason::LINK_REMOVED, $tenantId, $connectionId, $identity, linkId: $linkId);
    }

    /**
     * The identity's sessions through a domain link suspended because its scope
     * widened.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $linkId
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function identityLink(string $tenantId, string $connectionId, IdentityReference $identity, string $linkId): self
    {
        self::assertIds($tenantId, $connectionId, $linkId);

        return new self(RevocationScopeKind::IDENTITY_LINK, RevocationReason::SCOPE_WIDENED, $tenantId, $connectionId, $identity, linkId: $linkId);
    }

    /**
     * Refuse an empty tenant, connection or, for an identity scope, link id.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  ?string  $linkId
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertIds(string $tenantId, string $connectionId, ?string $linkId = null): void
    {
        if ($tenantId === '' || $connectionId === '') {
            throw new \InvalidArgumentException('A revocation scope names its tenant and connection.');
        }

        if ($linkId === '') {
            throw new \InvalidArgumentException('A revocation scope of a link names the link.');
        }
    }
}
