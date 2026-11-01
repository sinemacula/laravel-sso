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
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Reports how a completion at an assertion consumer service or a callback ended
 * (SSO-10.1, SSO-10.2, SSO-10.4), once per completion:
 *
 * - completed: `ResultVerified`, then `HandoffIssued`;
 * - refused after its response was verified: `ResultVerified`, then exactly one
 *   `FlowFailed` with the flow and the reason;
 * - refused before (a full limit, a method or a connection the endpoint does
 *   not take, a response no request matches, a refused consumption or
 *   validation): exactly one `FlowFailed`.
 *
 * Each event's context is built through the one projection
 * (`Events\EventContexts`) from what the completion had established: the
 * connection, its tenant and protocol once it was read; the application, the
 * purpose and the request's public reference once the request was consumed; the
 * identity (the one the result's link resolved to for a `sign_in`, the one the
 * request was started for for a `link` or a `reauthenticate`) and the session a
 * `reauthenticate` was started on. The public reference is the only flow
 * identifier it carries (SSO-9.8); never a subject, an attribute, the protocol
 * state, a nonce, a verifier, an assertion or a code (SSO-10.4).
 *
 * Each event is handed to `Events\AfterCommitDispatcher`: reported inside the
 * completion's transaction, it reaches listeners once that commits, and never
 * when it rolls back (SSO-10.5).
 *
 * It holds the projection and the dispatcher, both of which read the clock, the
 * request and the transaction from the container on each call, so nothing of
 * one completion is kept for the next (SSO-11.2).
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
     * Report how the completion of the flow ended: completed when the outcome
     * proceeds, refused for its reason otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\Flow  $flow
     * @param  \SineMacula\Laravel\Sso\Completion\StageOutcome  $outcome
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function report(Flow $flow, StageOutcome $outcome): void
    {
        $context = $this->context($outcome->state);
        $reason  = $outcome->reason;

        if ($outcome->state->result !== null) {
            $this->dispatcher->dispatch(new ResultVerified($context));
        }

        $this->dispatcher->dispatch($reason === null ? new HandoffIssued($context) : new FlowFailed($context, $flow, $reason));
    }

    /**
     * The context of the completion, with what it had established.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     *
     * @throws \InvalidArgumentException
     */
    private function context(CompletionState $state): EventContext
    {
        $connection = $state->connection;
        $consumed   = $state->consumed;
        $identity   = self::identity($state);

        return $this->contexts->make(
            connectionId: $connection?->id,
            tenantId: $connection?->tenant_id,
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
     * The identity the completion concerns: the one the result's link resolved
     * to for a `sign_in`, and the one the request was started for for a `link`
     * or a `reauthenticate`; none before the request was consumed.
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
