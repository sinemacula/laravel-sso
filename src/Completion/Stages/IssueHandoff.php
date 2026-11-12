<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Stages;

use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Contracts\ProviderSessionDeadline;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkReservations;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * The `handoff_issuance` step: asks the application policy again and issues the
 * code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IssueHandoff implements CompletionStage
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\ApplicationPolicy  $policy
     * @param  \SineMacula\Laravel\Sso\Contracts\ProviderSessionDeadline  $deadlines
     * @param  \SineMacula\Laravel\Sso\Contracts\HandoffIssuer  $issuer
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\Sso\Links\LinkReservations  $reservations
     */
    public function __construct(

        /** Whether the application allows sign-in through an external provider. */
        private ApplicationPolicy $policy,

        /** Whether the provider's session deadline limits the session. */
        private ProviderSessionDeadline $deadlines,

        /** Issues the handoff code. */
        private HandoffIssuer $issuer,

        /** The clock the code's expiry is read from. */
        private Clock $clock,

        /** Binds a reservation to the handoff issued for it. */
        private LinkReservations $reservations,
    ) {}

    /**
     * Ask the policy again, then issue the code.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     *
     * @throws \LogicException
     */
    #[\Override]
    public function run(CompletionState $state): StageOutcome
    {
        $application = $state->application          ?? throw new \LogicException('A handoff is issued once the request is consumed.');
        $request     = $state->authorizationRequest ?? throw new \LogicException('A handoff is issued once the request is consumed.');
        $result      = $state->result               ?? throw new \LogicException('A handoff is issued once the result is verified.');
        $connection  = $state->connection           ?? throw new \LogicException('A handoff is issued under the connection\'s lock.');

        if (!$this->policy->externalSignIn($application)->isAllowed()) {
            return StageOutcome::refuse($state, FailureReason::APPLICATION_NOT_ALLOWED);
        }

        $state     = $this->limited($state, $result);
        $candidate = $state->reservedCandidate;
        $grant     = new HandoffGrant(
            result: $result,
            challenge: S256Challenge::fromString($request->handoff_challenge),
            expiresAt: $candidate->expiresAt ?? $this->clock->now()->addSeconds($application->handoffTtlSeconds),
            trustVersion: $connection->trust_version,
            linkedIdentity: $state->linkedIdentity,
            identity: IdentityReference::fromColumns($request->identity_type, $request->identity_id),
            sessionId: $request->session_id,
            sessionNotAfter: $state->sessionNotAfter,
            linkId: $state->resolution?->linkId,
            reservationId: $candidate?->reservationId,
        );
        $issued = $this->issuer->issue($grant);

        if ($candidate !== null && $state->resolution !== null) {
            $state = $state->withResolution($state->resolution, $this->reservations->bindHandoff($candidate, $issued));
        }

        return StageOutcome::proceed($state->withHandoff($issued));
    }

    /**
     * The state with the provider's deadline as the session's latest end, when
     * the deadline contract says it limits the session.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return \SineMacula\Laravel\Sso\Completion\CompletionState
     */
    private function limited(CompletionState $state, VerifiedResult $result): CompletionState
    {
        $deadline = $result->authenticationContext->providerSessionDeadline;

        if ($deadline === null || !$this->deadlines->effect($result)->limitsSession()) {
            return $state;
        }

        return $state->withSessionNotAfter($deadline);
    }
}
