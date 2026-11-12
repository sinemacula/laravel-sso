<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Stages;

use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;

/**
 * The `provisioning` step: stops a genuinely unlinked `sign_in` with no
 * reservation at the provisioning boundary.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Provisioning implements CompletionStage
{
    /**
     * Stop a genuinely unlinked `sign_in` at the boundary.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     */
    #[\Override]
    public function run(CompletionState $state): StageOutcome
    {
        $unlinked = $state->resolution?->isAbsent() ?? false;

        if ($unlinked && $state->reservedCandidate === null && $state->consumed?->purpose === Purpose::SIGN_IN) {
            return StageOutcome::provision($state);
        }

        return StageOutcome::proceed($state);
    }
}
