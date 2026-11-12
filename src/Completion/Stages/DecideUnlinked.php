<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Stages;

use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;

/**
 * The `unlinked_decision` step: an unlinked `sign_in` ends with `unlinked`
 * unless its application allows unlinked handoffs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DecideUnlinked implements CompletionStage
{
    /**
     * Refuse an unlinked `sign_in` unless its application allows unlinked
     * handoffs.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     *
     * @throws \LogicException
     */
    #[\Override]
    public function run(CompletionState $state): StageOutcome
    {
        $application = $state->application ?? throw new \LogicException('An unlinked result is decided once the request is consumed.');

        if (self::isUnlinkedSignIn($state) && !$application->unlinkedHandoffs) {
            return StageOutcome::refuse($state, FailureReason::UNLINKED);
        }

        return StageOutcome::proceed($state);
    }

    /**
     * Whether the state is a `sign_in` with no identity and no reservation.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return bool
     *
     * @throws \LogicException
     */
    private static function isUnlinkedSignIn(CompletionState $state): bool
    {
        $consumed = $state->consumed ?? throw new \LogicException('An unlinked result is decided once the request is consumed.');

        return $consumed->purpose === Purpose::SIGN_IN && $state->linkedIdentity === null && $state->reservedCandidate === null;
    }
}
