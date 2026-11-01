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
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * The `handoff_issuance` step (SSO-9.2, SSO-6.10, SSO-9.10), the last of a
 * completion, inside its locked transaction:
 *
 * 1. the application policy is asked again (AUTH-3.7): an application that no
 *    longer allows sign-in through an external provider refuses with
 *    `application_not_allowed`;
 * 2. a result carrying the provider's session deadline asks the bound
 *    `Contracts\ProviderSessionDeadline` whether it limits the application's
 *    session; when it does, the deadline is the session's latest end;
 * 3. the bound `Contracts\HandoffIssuer` issues a code for a
 *    `Handoffs\HandoffGrant` of the result, the request's S256 challenge, an
 *    expiry of the application's handoff lifetime from now, the identity the
 *    link resolved to, the identity and the session the request was started
 *    for, the enforcement version checked and the session's latest end;
 * 4. the issued handoff goes on with the state.
 *
 * An issuer signals failure by throwing, which rolls the completion back as a
 * server error (SSO-11.4); it is never turned into a refusal.
 *
 * It holds the policy, the deadline contract, the issuer and the clock, none of
 * which keeps anything of one completion for the next (SSO-11.2).
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
     */
    public function __construct(

        /** Whether the application allows sign-in through an external provider. */
        private ApplicationPolicy $policy,

        /** Whether the provider's session deadline limits the application's session. */
        private ProviderSessionDeadline $deadlines,

        /** Issues the handoff code. */
        private HandoffIssuer $issuer,

        /** The clock the code's expiry is read from. */
        private Clock $clock,
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

        if (!$this->policy->externalSignIn($application)->isAllowed()) {
            return StageOutcome::refuse($state, FailureReason::APPLICATION_NOT_ALLOWED);
        }

        $state = $this->limited($state, $result);
        $grant = new HandoffGrant(
            result: $result,
            challenge: S256Challenge::fromString($request->handoff_challenge),
            expiresAt: $this->clock->now()->addSeconds($application->handoffTtlSeconds),
            linkedIdentity: $state->linkedIdentity,
            identity: IdentityReference::fromColumns($request->identity_type, $request->identity_id),
            sessionId: $request->session_id,
            enforcementVersion: $state->enforcementVersion,
            sessionNotAfter: $state->sessionNotAfter,
        );

        return StageOutcome::proceed($state->withHandoff($this->issuer->issue($grant)));
    }

    /**
     * The state with the session's latest end, when the result carries the
     * provider's session deadline and the deadline contract says it limits the
     * application's session.
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
