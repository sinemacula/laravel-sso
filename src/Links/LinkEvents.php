<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Events\AfterCommitDispatcher;
use SineMacula\Laravel\Sso\Events\EventContexts;
use SineMacula\Laravel\Sso\Events\LinkActivated;
use SineMacula\Laravel\Sso\Events\LinkConfirmed;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\LinkRemoved;
use SineMacula\Laravel\Sso\Events\LinkSuspended;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Reports a link created, removed, activated, confirmed or suspended (SSO-8.4,
 * SSO-8.8, SSO-10.3): each method builds the event's context through the one
 * projection (`Events\EventContexts`), from the connection's id, tenant and
 * protocol, the identity the link associates and the acting identity the
 * application passed, and hands the event to `Events\AfterCommitDispatcher`, so
 * it reaches listeners once the transaction on the storage connection commits,
 * and never when it rolls back (SSO-10.5).
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
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
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
        SsoConnection $connection,
        IdentityReference $identity,
        LinkOrigin $origin,
        ?ActingIdentity $actor = null,
        ?string $application = null,
        ?Purpose $purpose = null,
        ?RequestReference $reference = null,
    ): void {
        $context = $this->contexts->make(
            connectionId: $connection->getConnectionId(),
            connectionTenantId: $connection->getTenantId(),
            protocol: $connection->getProtocol(),
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
            connectionTenantId: $connection->tenant_id,
            protocol: $connection->protocol,
            identityMorphClass: $identity->type,
            identityId: $identity->id,
            actingIdentityMorphClass: $actor?->type,
            actingIdentityId: $actor?->id,
        );

        $this->dispatcher->dispatch(new LinkRemoved($context));
    }

    /**
     * Report a reservation activated by the redemption of its handoff: a link
     * created by a verified domain, then its activation, which carries what the
     * application needs to notify the person on their existing channels and
     * never the email the provider supplied.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $linkId
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function activated(Connection $connection, IdentityReference $identity, string $linkId, string $application, RequestReference $reference): void
    {
        $this->created($connection, $identity, LinkOrigin::VERIFIED_DOMAIN, null, $application, Purpose::SIGN_IN, $reference);

        $context = $this->contexts->make(
            connectionId: $connection->id,
            connectionTenantId: $connection->tenant_id,
            protocol: $connection->protocol,
            application: $application,
            purpose: Purpose::SIGN_IN->value,
            requestReference: $reference->value,
            identityMorphClass: $identity->type,
            identityId: $identity->id,
        );

        $this->dispatcher->dispatch(new LinkActivated($linkId, $context));
    }

    /**
     * Report the identity's link confirmed through the `link` purpose.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $application
     * @param  ?\SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function confirmed(SsoConnection $connection, IdentityReference $identity, ?string $application = null, ?RequestReference $reference = null): void
    {
        $context = $this->contexts->make(
            connectionId: $connection->getConnectionId(),
            connectionTenantId: $connection->getTenantId(),
            protocol: $connection->getProtocol(),
            application: $application,
            purpose: Purpose::LINK->value,
            requestReference: $reference?->value,
            identityMorphClass: $identity->type,
            identityId: $identity->id,
        );

        $this->dispatcher->dispatch(new LinkConfirmed($context));
    }

    /**
     * Report the identity's link through the connection suspended.
     *
     * @param  string  $connectionId
     * @param  string  $tenantId
     * @param  string  $protocol
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function suspended(string $connectionId, string $tenantId, string $protocol, IdentityReference $identity): void
    {
        $context = $this->contexts->make(
            connectionId: $connectionId,
            connectionTenantId: $tenantId,
            protocol: $protocol,
            identityMorphClass: $identity->type,
            identityId: $identity->id,
        );

        $this->dispatcher->dispatch(new LinkSuspended($context));
    }
}
