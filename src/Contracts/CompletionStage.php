<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\StageOutcome;

/**
 * Completion stage contract (SSO-5.6): one step of a completion, registered for
 * one case of `Completion\Enums\CompletionStep` and run in that case's order:
 * it reads what the steps before it established from the state, and either
 * passes the state on, with what it established added, or refuses the
 * completion with a reason.
 *
 * A stage refuses expected failures as values; a database error, a store that
 * cannot answer or a misconfiguration propagates as a server error (SSO-11.4),
 * never as a refusal. A stage of a locked step runs inside the completion's
 * transaction with the connection's and the request's rows locked, and every
 * read that decides a write there is a locking read. A stage dispatches no
 * event: the pipeline reports the completion once it has committed. A stage
 * keeps nothing of one completion for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface CompletionStage
{
    /**
     * Run the step on the state.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     */
    public function run(CompletionState $state): StageOutcome;
}
