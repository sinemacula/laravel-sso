<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Events\AfterCommitDispatcher;
use SineMacula\Laravel\Sso\Events\EventContexts;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\LinkRemoved;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Reports a link created and a link removed (SSO-8.4, SSO-10.3): each method
 * builds the event's context through the one projection
 * (`Events\EventContexts`), from the connection's id, tenant and protocol, the
 * identity the link associates and the acting identity the application passed,
 * and hands the event to `Events\AfterCommitDispatcher`, so it reaches
 * listeners once the transaction on the storage connection commits, and never
 * when it rolls back (SSO-10.5).
 *
 * A creation made by a flow adds its application, its purpose and the request's
 * public reference, the only flow identifier an event carries (SSO-9.8).
 * Neither event carries the issuer's subject. A change is reported inside the
 * transaction that made it, after the write (and, for a removal, after the
 * revocation), once; never for a refusal.
 *
 * It holds the projection and the dispatcher, so nothing of one request is kept
 * for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LinkEvents
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
     * Report a link created through the connection for the identity, how it was
     * made, and the flow that made it when there was one.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @param  ?string  $application
     * @param  ?\SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @return void
     *
     * @throws \InvalidArgumentException
     *
     * @SuppressWarnings("php:S107")
     */
    public function created(
        Connection $connection,
        IdentityReference $identity,
        LinkOrigin $origin,
        ?ActingIdentity $actor = null,
        ?string $application = null,
        ?Purpose $purpose = null,
        ?RequestReference $reference = null,
    ): void {
        $context = $this->contexts->make(
            connectionId: $connection->id,
            tenantId: $connection->tenant_id,
            protocol: $connection->protocol,
            application: $application,
            purpose: $purpose?->value,
            requestReference: $reference?->value,
            identityMorphClass: $identity->type,
            identityId: $identity->id,
            actingIdentityMorphClass: $actor?->type,
            actingIdentityId: $actor?->id,
        );

        $this->dispatcher->dispatch(new LinkCreated($context, $origin));
    }

    /**
     * Report the identity's link through the connection removed.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?\SineMacula\Laravel\Sso\Administration\ActingIdentity  $actor
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function removed(Connection $connection, IdentityReference $identity, ?ActingIdentity $actor = null): void
    {
        $context = $this->contexts->make(
            connectionId: $connection->id,
            tenantId: $connection->tenant_id,
            protocol: $connection->protocol,
            identityMorphClass: $identity->type,
            identityId: $identity->id,
            actingIdentityMorphClass: $actor?->type,
            actingIdentityId: $actor?->id,
        );

        $this->dispatcher->dispatch(new LinkRemoved($context));
    }
}
