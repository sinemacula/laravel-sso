<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Administration;

use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Events\AfterCommitDispatcher;
use SineMacula\Laravel\Sso\Events\EnforcementChanged;
use SineMacula\Laravel\Sso\Events\EventContexts;
use SineMacula\Laravel\Sso\Events\ExemptionUsed;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;

/**
 * Dispatches the events for enforcement changes and exemptions used.
 *
 * Call inside the change's transaction, after the write and any revocation.
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
     * Report the tenant's enforcement as the row now holds it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\TenantEnforcement  $enforcement
     * @param  string  $version
     * @param  ?string  $previousVersion
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     */
    public function changed(TenantEnforcement $enforcement, string $version, ?string $previousVersion, ?Caller $caller, ClientContext $client): void
    {
        $context = $this->contexts->make(
            $client,
            connectionTenantId: $enforcement->tenant_id,
            actingIdentityMorphClass: $caller?->identity->type,
            actingIdentityId: $caller?->identity->id,
        );

        $ids = array_values(array_unique($enforcement->connection_ids));

        sort($ids, SORT_STRING);

        $this->dispatcher->dispatch(new EnforcementChanged($context, $enforcement->enabled, $ids, $version, $previousVersion));
    }

    /**
     * Report a session established under an exemption from the policy.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?string  $sessionId
     * @return void
     */
    public function exemptionUsed(EnforcementPolicy $policy, string $application, IdentityReference $identity, ClientContext $client, ?string $sessionId = null): void
    {
        $context = $this->contexts->make(
            $client,
            connectionTenantId: $policy->enforcingTenantId,
            application: $application,
            identityMorphClass: $identity->type,
            identityId: $identity->id,
            tenantId: $policy->tenantId,
            sessionId: $sessionId,
        );

        $this->dispatcher->dispatch(new ExemptionUsed($context, $policy->version));
    }
}
