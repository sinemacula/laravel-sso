<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Stages;

use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * The `enforcement` step: the connection must satisfy its tenant's policy,
 * judged from the locked rule when there is one.
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
