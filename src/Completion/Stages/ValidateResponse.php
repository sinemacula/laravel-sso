<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Stages;

use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\ResultBuilder;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;

/**
 * The `validation` step (SSO-5.6, SSO-6, SSO-7): the connection's driver
 * validates the response against the request just consumed for it, outside any
 * transaction, since a driver may fetch (an OIDC token request).
 *
 * A connection that is no longer usable (disabled since the start, its protocol
 * switched off, its settings incomplete) is refused with
 * `connection_unavailable` before its driver is asked, so no provider is
 * contacted for a connection that cannot complete; the request stays consumed.
 * The locked steps ask again under the connection's lock, since the connection
 * may change while the driver validates.
 *
 * A response the driver refuses is refused with its reason. A verified one goes
 * on with its claims, the `Protocols\ReplayRecord` the driver asked for, if any
 * (recorded by the `replay_recording` step under the completion's locks), the
 * `Protocols\TransitionReceipt` of a key rotation its own validation made, if
 * any (judged under the completion's locks), and the `Results\VerifiedResult`
 * built from them by `Completion\ResultBuilder`.
 *
 * It holds the drivers' registry and the builder, neither of which keeps
 * anything of one completion for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ValidateResponse implements CompletionStage
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     * @param  \SineMacula\Laravel\Sso\Completion\ResultBuilder  $results
     */
    public function __construct(

        /** The protocol drivers, and whether a connection is usable. */
        private ProtocolManager $protocols,

        /** Builds the verified result from what the driver verified. */
        private ResultBuilder $results,
    ) {}

    /**
     * Ask the connection's driver to validate the response, and build the
     * verified result from what it verified.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     *
     * @throws \LogicException
     */
    #[\Override]
    public function run(CompletionState $state): StageOutcome
    {
        $connection = $state->connection ?? throw new \LogicException('A response is validated once its connection is read.');
        $consumed   = $state->consumed   ?? throw new \LogicException('A response is validated once its request is consumed.');

        if (!$this->protocols->isUsable($connection)) {
            return StageOutcome::refuse($state, FailureReason::CONNECTION_UNAVAILABLE);
        }

        $completion = $this->protocols->protocol($connection->protocol)->complete($connection, $state->request, $consumed);
        $claims     = $completion->claims;

        if ($claims === null) {
            return StageOutcome::refuse($state, $completion->reason ?? throw new \LogicException('A refused completion holds its reason.'));
        }

        $verified = $state->withClaims($claims)->withResult($this->results->build($claims, $connection, $consumed));
        $replayed = $completion->replay === null ? $verified : $verified->withReplay($completion->replay);

        return StageOutcome::proceed($completion->receipt === null ? $replayed : $replayed->withTransitionReceipt($completion->receipt));
    }
}
