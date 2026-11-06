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
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Reports how a start of an authorisation request ended (SSO-10.1, SSO-10.2):
 * `AuthorizationRequestStarted` for a request stored, and exactly one
 * `FlowFailed` (`Flow::AUTHORIZATION_REQUEST`) with its reason for a refused
 * start, a discovery fallback included. Each event's context is built through
 * the one projection (`Events\EventContexts`) and handed to
 * `Events\AfterCommitDispatcher`, so it reaches listeners once the request
 * commits, and never when the caller's transaction rolls it back (SSO-10.5).
 *
 * A started request's context names its connection, the connection's tenant and
 * protocol, the application, the purpose, the public reference, and the
 * identity and session it was started for. A refusal's names the purpose, the
 * identity and the session the application gave, and as much more as the start
 * had established when it was refused: the application once admitted, the
 * connection once found, the public reference once made. The public reference
 * is the only flow identifier either carries (SSO-9.8); neither holds the
 * protocol state, the nonce, a verifier or a challenge (SSO-10.4).
 *
 * Every method takes the client the action is taken for (`Http\ClientContext`),
 * whose IP address and user agent the event's context carries; nothing reads
 * the request being served. It holds the projection and the dispatcher, which
 * read the clock and the transaction from the container on each call, so
 * nothing of one request is kept for the next (SSO-11.2).
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
     * Report the request started through the connection. Called inside the
     * transaction that stored it, after the write.
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
     * Report a start refused for the reason, with what the start had
     * established.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $sessionId
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
        ?IdentityReference $identity,
        ?string $sessionId,
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
            identityMorphClass: $identity?->type,
            identityId: $identity?->id,
            sessionId: $sessionId,
        );

        $this->dispatcher->dispatch(new FlowFailed($context, Flow::AUTHORIZATION_REQUEST, $reason));
    }
}
