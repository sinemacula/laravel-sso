<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Stages;

use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * The `enforcement` step (SSO-4.1, SSO-4.6, SSO-9.10): the policy of the
 * connection's tenant on the request's application. Under the package's default
 * contract with the feature on, it is the one the pipeline judged from the rows
 * it locked at the start of the locked steps (the enforcing tenant's rule, then
 * the connections, `CompletionPipeline`), carried on the state, so a change to
 * the rule waits for the completion's transaction; otherwise the bound
 * `Contracts\Enforcement` is asked now. A policy that requires sign-in through
 * a satisfying connection, and that this connection does not satisfy, refuses
 * with `enforcement_unsatisfied`; a policy that requires nothing is satisfied
 * by every connection.
 *
 * The state goes on unchanged otherwise: the session keeps the version its
 * redemption judges under its own locks, not the one checked here. No exemption
 * is consulted here, nor at redemption: only an adapter's
 * `Enforcement\ExemptionGate` asks the exemption contract, for a session it
 * establishes, and redeeming the handoff rechecks enforcement against the state
 * at redemption.
 *
 * It holds the enforcement contract, which keeps nothing of one completion for
 * the next (SSO-11.2). A database error propagates (SSO-11.4).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CheckEnforcement implements CompletionStage
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Enforcement  $enforcement
     */
    public function __construct(

        /** Answers the enforcement of a tenant on an application. */
        private Enforcement $enforcement,
    ) {}

    /**
     * Refuse a connection that does not satisfy its tenant's enforcement.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     *
     * @throws \LogicException
     */
    #[\Override]
    public function run(CompletionState $state): StageOutcome
    {
        $connection  = $state->connection        ?? throw new \LogicException('Enforcement is checked once the connection is read.');
        $application = $state->application       ?? throw new \LogicException('Enforcement is checked once the request is consumed.');
        $policy      = $state->enforcementPolicy ?? $this->enforcement->policy($connection->tenant_id, $application->name);

        if (!$policy->isSatisfiedBy($connection->id)) {
            return StageOutcome::refuse($state, FailureReason::ENFORCEMENT_UNSATISFIED);
        }

        return StageOutcome::proceed($state);
    }
}
