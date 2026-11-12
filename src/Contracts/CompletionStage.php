<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\StageOutcome;

/**
 * One step of a completion, registered for a `Completion\Enums\CompletionStep`
 * case and run in that case's order.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface CompletionStage
{
    /**
     * Refuse expected failures as values and let other errors propagate. In a
     * locked step, every read that decides a write must be a locking read.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     */
    public function run(CompletionState $state): StageOutcome;
}
