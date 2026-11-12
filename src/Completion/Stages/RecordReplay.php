<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Stages;

use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;

/**
 * The `replay_recording` step: records the verified response against replay,
 * first in the locked transaction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecordReplay implements CompletionStage
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\SingleUseStore  $store
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** Records each response once. */
        private SingleUseStore $store,

        /** The clock the record's expiry is judged against. */
        private Clock $clock,
    ) {}

    /**
     * Record what the driver asked to record, once, refusing a record already
     * expired.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     *
     * @throws \Throwable
     */
    #[\Override]
    public function run(CompletionState $state): StageOutcome
    {
        $replay = $state->replay;

        if ($replay === null) {
            return StageOutcome::proceed($state);
        }

        if ($replay->until <= $this->clock->now()) {
            return StageOutcome::refuse($state, FailureReason::ASSERTION_EXPIRED);
        }

        $outcome = $this->store->record($replay->namespace, $replay->key(), $replay->until);

        return $outcome === SingleUseOutcome::RECORDED ? StageOutcome::proceed($state) : StageOutcome::refuse($state, FailureReason::REPLAYED);
    }
}
