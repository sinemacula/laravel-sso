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
 * The `replay_recording` step (SSO-6.6, SSO-11.5): the first step of the
 * completion's locked transaction, with the connection's row and the request's
 * locked, so it runs only after the driver's validation passed and before any
 * downstream effect (link resolution, enforcement, a handoff code).
 *
 * A result the driver asked nothing to record goes on. Otherwise the record is
 * made through the single-use store in its namespace until its expiry, inside
 * the transaction, so a completion that rolls back records nothing: `recorded`
 * goes on; `seen` is refused with `replayed`. A record whose expiry is no
 * longer after now (the response stopped being acceptable while it was
 * validated) is refused with `assertion_expired`, recording nothing. A store
 * that cannot answer throws, which rolls the completion back as a server error
 * (SSO-11.4): a failure to record is never a pass.
 *
 * It holds the store and the clock, neither of which keeps anything of one
 * completion for the next (SSO-11.2).
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
     * Record what the driver asked to record, once.
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
