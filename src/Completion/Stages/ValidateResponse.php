<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Stages;

use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\ResultBuilder;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Completion\VerifiedDeadlines;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;

/**
 * The `validation` step: the driver validates the response outside any
 * transaction, since it may fetch.
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
     * @param  \SineMacula\Laravel\Sso\Completion\VerifiedDeadlines  $deadlines
     */
    public function __construct(

        /** The protocol drivers, and whether a connection is usable. */
        private ProtocolManager $protocols,

        /** Builds the verified result from what the driver verified. */
        private ResultBuilder $results,

        /** When a verified response stops being valid. */
        private VerifiedDeadlines $deadlines,
    ) {}

    /**
     * Refuse an unusable connection before any provider call, else validate and
     * build the verified result.
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

        $completion = $this->protocols->protocol($connection->protocol)->complete($connection, $state->request, $consumed, $state->client);
        $claims     = $completion->claims;

        if ($claims === null) {
            return StageOutcome::refuse($state, $completion->reason ?? throw new \LogicException('A refused completion holds its reason.'));
        }

        $verified = $state->withClaims($claims)
            ->withResult($this->results->build($claims, $connection, $consumed))
            ->withValidation($connection->linking_version, $this->deadlines->until($state->authorizationRequest?->expires_at));
        $replayed = $completion->replay === null ? $verified : $verified->withReplay($completion->replay);

        return StageOutcome::proceed($completion->receipt === null ? $replayed : $replayed->withTransitionReceipt($completion->receipt));
    }
}
