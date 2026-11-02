<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Revocation;

use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind;

/**
 * Which sessions the package asks the `Contracts\SessionRevocation` contract to
 * revoke, and why (SSO-4.5, SSO-8.8): one of four scopes, built only through
 * its named constructors.
 *
 * - `tenant()`: after a change to a tenant's enforcement, the sessions active
 *   in it (or in a tenant whose rule it is) that the policy now in force no
 *   longer allows, carried as `policy`: those not established through one of
 *   its satisfying connections, unless the exemption contract exempts their
 *   identity.
 * - `connection()`: every session established through a connection that was
 *   disabled or deleted.
 * - `identityInConnection()`: the identity's sessions established through a
 *   connection whose link to it was removed.
 * - `identityLink()`: the identity's sessions established through one link by a
 *   verified domain, suspended because the identity came to hold a principal
 *   outside the connection's tenant (`Linking\ScopeWidening`). An adapter whose
 *   sessions do not record their link revokes the identity's sessions through
 *   the connection instead, which is broader and never narrower.
 *
 * It holds ids, enum cases and the policy, never a secret, so an adapter may
 * log it.
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

        /** The connection the sessions were established through, for the connection and identity scopes only. */
        public ?string $connectionId = null,

        /** The identity whose sessions are revoked, for the identity scopes only. */
        public ?IdentityReference $identity = null,

        /** The enforcement now in force, for the tenant scope only. */
        public ?EnforcementPolicy $policy = null,

        /** The link the sessions were established through, for the link scope only. */
        public ?string $linkId = null,
    ) {}

    /**
     * The sessions the tenant's enforcement, as it now is, no longer allows.
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
     * The identity's sessions established through the connection, whose link to
     * it was removed.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function identityInConnection(string $tenantId, string $connectionId, IdentityReference $identity): self
    {
        self::assertIds($tenantId, $connectionId);

        return new self(RevocationScopeKind::IDENTITY_CONNECTION, RevocationReason::LINK_REMOVED, $tenantId, $connectionId, $identity);
    }

    /**
     * The identity's sessions established through the link, suspended because
     * the identity's scope widened.
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
        self::assertIds($tenantId, $connectionId);

        if ($linkId === '') {
            throw new \InvalidArgumentException('A revocation scope of a link names the link.');
        }

        return new self(RevocationScopeKind::IDENTITY_LINK, RevocationReason::SCOPE_WIDENED, $tenantId, $connectionId, $identity, linkId: $linkId);
    }

    /**
     * Refuse an empty tenant or connection id.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertIds(string $tenantId, string $connectionId): void
    {
        if ($tenantId === '' || $connectionId === '') {
            throw new \InvalidArgumentException('A revocation scope names its tenant and connection.');
        }
    }
}
