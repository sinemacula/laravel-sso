<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Administration;

use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Events\AfterCommitDispatcher;
use SineMacula\Laravel\Sso\Events\EnforcementChanged;
use SineMacula\Laravel\Sso\Events\EventContexts;
use SineMacula\Laravel\Sso\Events\ExemptionUsed;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;

/**
 * Reports a tenant's enforcement changed and an exemption used (SSO-4.4,
 * SSO-4.5, SSO-10.3): each method builds the event's context through the one
 * projection (`Events\EventContexts`) and hands the event to
 * `Events\AfterCommitDispatcher`, so it reaches listeners once the transaction
 * on the storage connection commits, at once when none is open, and never when
 * it rolls back (SSO-10.5).
 *
 * A change is reported inside the transaction that made it, after the write and
 * after the revocation it needed, once per change; never for a refusal or a
 * no-op. It holds the projection and the dispatcher, so nothing of one request
 * is kept for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EnforcementEvents
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContexts  $contexts
     * @param  \SineMacula\Laravel\Sso\Events\AfterCommitDispatcher  $dispatcher
     */
    public function __construct(

        /** The projection every event's context is built through. */
        private EventContexts $contexts,

        /** The dispatcher that waits for the change to commit. */
        private AfterCommitDispatcher $dispatcher,
    ) {}

    /**
     * Report the tenant's enforcement as the row now holds it, with the version
     * it replaced.
     *
     * @param  \SineMacula\Laravel\Sso\Models\TenantEnforcement  $enforcement
     * @param  ?string  $previousVersion
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return void
     */
    public function changed(TenantEnforcement $enforcement, ?string $previousVersion, ?ActingIdentity $actor): void
    {
        $context = $this->contexts->make(
            tenantId: $enforcement->tenant_id,
            actingIdentityMorphClass: $actor?->type,
            actingIdentityId: $actor?->id,
        );

        $ids = array_values(array_unique($enforcement->connection_ids));

        sort($ids, SORT_STRING);

        $this->dispatcher->dispatch(new EnforcementChanged($context, $enforcement->enabled, $ids, $enforcement->version, $previousVersion));
    }

    /**
     * Report a session established in the policy's tenant, on the application,
     * for the identity, under an exemption from the policy; the session's id
     * when the caller has one.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
     * @return void
     */
    public function exemptionUsed(EnforcementPolicy $policy, string $application, IdentityReference $identity, ?string $sessionId = null): void
    {
        $context = $this->contexts->make(
            tenantId: $policy->enforcingTenantId,
            application: $application,
            identityMorphClass: $identity->type,
            identityId: $identity->id,
            activeTenantId: $policy->tenantId,
            sessionId: $sessionId,
        );

        $this->dispatcher->dispatch(new ExemptionUsed($context, $policy->version));
    }
}
