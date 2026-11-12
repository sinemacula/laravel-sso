<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Links;

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
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Reports link lifecycle events after the storage transaction commits.
 *
 * Call inside the transaction that made the change, after the write.
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
     * Report a link created, with the flow that made it when there was one.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkOrigin  $origin
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
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
        ClientContext $client,
        ?Caller $caller = null,
        ?string $application = null,
        ?Purpose $purpose = null,
        ?RequestReference $reference = null,
    ): void {
        $context = $this->contexts->make(
            $client,
            connectionId: $connection->getConnectionId(),
            connectionTenantId: $connection->getTenantId(),
            protocol: $connection->getProtocol(),
            application: $application,
            purpose: $purpose?->value,
            requestReference: $reference?->value,
            identityMorphClass: $identity->type,
            identityId: $identity->id,
            actingIdentityMorphClass: $caller?->identity->type,
            actingIdentityId: $caller?->identity->id,
        );

        $this->dispatcher->dispatch(new LinkCreated($context, $origin));
    }

    /**
     * Report the identity's link through the connection removed.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function removed(Connection $connection, IdentityReference $identity, ClientContext $client, ?Caller $caller = null): void
    {
        $context = $this->contexts->make(
            $client,
            connectionId: $connection->id,
            connectionTenantId: $connection->tenant_id,
            protocol: $connection->protocol,
            identityMorphClass: $identity->type,
            identityId: $identity->id,
            actingIdentityMorphClass: $caller?->identity->type,
            actingIdentityId: $caller?->identity->id,
        );

        $this->dispatcher->dispatch(new LinkRemoved($context));
    }

    /**
     * Report a reservation activated: `LinkCreated`, then `LinkActivated`.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $linkId
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function activated(Connection $connection, IdentityReference $identity, string $linkId, string $application, RequestReference $reference, ClientContext $client): void
    {
        $this->created($connection, $identity, LinkOrigin::VERIFIED_DOMAIN, $client, null, $application, Purpose::SIGN_IN, $reference);

        $context = $this->contexts->make(
            $client,
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
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?string  $application
     * @param  ?\SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function confirmed(SsoConnection $connection, IdentityReference $identity, ClientContext $client, ?string $application = null, ?RequestReference $reference = null): void
    {
        $context = $this->contexts->make(
            $client,
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
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function suspended(string $connectionId, string $tenantId, string $protocol, IdentityReference $identity, ClientContext $client): void
    {
        $context = $this->contexts->make(
            $client,
            connectionId: $connectionId,
            connectionTenantId: $tenantId,
            protocol: $protocol,
            identityMorphClass: $identity->type,
            identityId: $identity->id,
        );

        $this->dispatcher->dispatch(new LinkSuspended($context));
    }
}
