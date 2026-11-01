<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Stages;

use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;

/**
 * A completion step whose feature is not built yet: it passes every state on
 * unchanged, so the completion runs as if the step were absent. Each such step
 * is a class of its own, registered for its case of
 * `Completion\Enums\CompletionStep`, so building the feature replaces that one
 * class and nothing else.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract readonly class UnbuiltStage implements CompletionStage
{
    /**
     * Pass the state on unchanged.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     */
    #[\Override]
    final public function run(CompletionState $state): StageOutcome
    {
        return StageOutcome::proceed($state);
    }
}
