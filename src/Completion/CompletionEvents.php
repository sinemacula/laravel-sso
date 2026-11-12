<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion;

use SineMacula\Laravel\Sso\Events\AfterCommitDispatcher;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\EventContexts;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\HandoffIssued;
use SineMacula\Laravel\Sso\Events\ResultVerified;
use SineMacula\Laravel\Sso\Events\UnsolicitedResponseReinitiated;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Connection;

/**
 * Reports how a completion ended, once, after its transaction commits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CompletionEvents
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

        /** The dispatcher that waits for the completion to commit. */
        private AfterCommitDispatcher $dispatcher,
    ) {}

    /**
     * Report how the completion ended.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\Flow  $flow
     * @param  \SineMacula\Laravel\Sso\Completion\StageOutcome  $outcome
     * @param  bool  $verifiedReported
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function report(Flow $flow, StageOutcome $outcome, bool $verifiedReported = false): void
    {
        $context = $this->context($outcome->state);
        $reason  = $outcome->reason;

        if ($outcome->state->result !== null && !$verifiedReported) {
            $this->dispatcher->dispatch(new ResultVerified($context));
        }

        $this->dispatcher->dispatch($reason === null ? new HandoffIssued($context) : new FlowFailed($context, $flow, $reason));
    }

    /**
     * Report a result verified that stopped at the provisioning boundary.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function verified(CompletionState $state): void
    {
        $this->dispatcher->dispatch(new ResultVerified($this->context($state)));
    }

    /**
     * Report an unsolicited response re-initiated, naming the connection only.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function reinitiated(Connection $connection, ClientContext $client): void
    {
        $context = $this->contexts->make($client, connectionId: $connection->id, connectionTenantId: $connection->tenant_id, protocol: $connection->protocol);

        $this->dispatcher->dispatch(new UnsolicitedResponseReinitiated($context));
    }

    /**
     * The event context of what the completion had established.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     *
     * @throws \InvalidArgumentException
     */
    public function context(CompletionState $state): EventContext
    {
        $connection = $state->connection;
        $consumed   = $state->consumed;
        $identity   = self::identity($state);

        return $this->contexts->make(
            $state->client,
            connectionId: $connection?->id,
            connectionTenantId: $connection?->tenant_id,
            protocol: $connection?->protocol,
            application: $state->application?->name,
            purpose: $consumed?->purpose->value,
            requestReference: $consumed?->reference->value,
            identityMorphClass: $identity?->type,
            identityId: $identity?->id,
            sessionId: $state->authorizationRequest?->session_id,
        );
    }

    /**
     * The linked identity of a `sign_in`, or the identity a `link` or
     * `reauthenticate` was started for.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return ?\SineMacula\Laravel\Sso\Identities\IdentityReference
     *
     * @throws \InvalidArgumentException
     */
    private static function identity(CompletionState $state): ?IdentityReference
    {
        $request = $state->authorizationRequest;

        return match ($state->consumed?->purpose) {
            Purpose::SIGN_IN                       => $state->linkedIdentity,
            Purpose::LINK, Purpose::REAUTHENTICATE => IdentityReference::fromColumns($request?->identity_type, $request?->identity_id),
            null                                   => null,
        };
    }
}
