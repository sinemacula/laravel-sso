<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Stages;

use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Enums\CorrelationKind;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;

/**
 * The `correlation` step (SSO-5.6): the connection's driver reads which
 * authorisation request the response answers, and validates nothing, outside
 * any transaction.
 *
 * A solicited response goes on with its correlation. A response nothing in it
 * correlates is refused with `request_unknown`, with no trusted redirect target
 * (SSO-5.7). An unsolicited SAML response is refused the same way for now: its
 * arm of the match below is the seam where IdP-initiated re-initiation
 * (SSO-5.8) answers it with the connection's start URL, consuming no request.
 *
 * It holds the drivers' registry, which keeps nothing of one completion for the
 * next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CorrelateResponse implements CompletionStage
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $protocols
     */
    public function __construct(

        /** The protocol drivers. */
        private ProtocolManager $protocols,
    ) {}

    /**
     * Ask the connection's driver which request the response answers.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     *
     * @throws \LogicException
     */
    #[\Override]
    public function run(CompletionState $state): StageOutcome
    {
        $connection  = $state->connection ?? throw new \LogicException('A response is correlated once its connection is read.');
        $correlation = $this->protocols->protocol($connection->protocol)->correlate($connection, $state->request);

        return match ($correlation->kind) {
            CorrelationKind::SOLICITED => StageOutcome::proceed($state->withCorrelation($correlation)),

            // The seam for IdP-initiated re-initiation (SSO-5.8): until it is
            // built, an unsolicited response is answered as an uncorrelated one
            CorrelationKind::UNSOLICITED  => StageOutcome::refuse($state, FailureReason::REQUEST_UNKNOWN),
            CorrelationKind::UNCORRELATED => StageOutcome::refuse($state, FailureReason::REQUEST_UNKNOWN),
        };
    }
}
