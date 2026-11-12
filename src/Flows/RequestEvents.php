<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Flows;

use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Events\AfterCommitDispatcher;
use SineMacula\Laravel\Sso\Events\AuthorizationRequestStarted;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\EventContexts;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Reports how a start of an authorisation request ended, after its transaction
 * commits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RequestEvents
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

        /** The dispatcher that waits for the request to commit. */
        private AfterCommitDispatcher $dispatcher,
    ) {}

    /**
     * Report the request started, from inside the transaction that stored it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function started(Connection $connection, AuthorizationRequest $request, ClientContext $client): void
    {
        $context = $this->contexts->make(
            $client,
            connectionId: $connection->id,
            connectionTenantId: $connection->tenant_id,
            protocol: $connection->protocol,
            application: $request->application,
            purpose: $request->purpose->value,
            requestReference: $request->reference,
            identityMorphClass: $request->identity_type,
            identityId: $request->identity_id,
            sessionId: $request->session_id,
        );

        $this->dispatcher->dispatch(new AuthorizationRequestStarted($context));
    }

    /**
     * Report a start refused, with what it had established.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Applications\Application  $application
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @return void
     *
     * @throws \InvalidArgumentException
     *
     * @SuppressWarnings("php:S107")
     */
    public function failed(
        FailureReason $reason,
        Purpose $purpose,
        ?Caller $caller,
        ClientContext $client,
        ?Application $application = null,
        ?Connection $connection = null,
        ?RequestReference $reference = null,
    ): void {
        $context = $this->contexts->make(
            $client,
            connectionId: $connection?->id,
            connectionTenantId: $connection?->tenant_id,
            protocol: $connection?->protocol,
            application: $application?->name,
            purpose: $purpose->value,
            requestReference: $reference?->value,
            identityMorphClass: $caller?->identity->type,
            identityId: $caller?->identity->id,
            sessionId: $purpose->bindsSession() ? $caller?->sessionId : null,
        );

        $this->dispatcher->dispatch(new FlowFailed($context, Flow::AUTHORIZATION_REQUEST, $reason));
    }
}
