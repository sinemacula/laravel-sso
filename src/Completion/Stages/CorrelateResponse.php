<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Stages;

use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Contracts\ProtocolDriver;
use SineMacula\Laravel\Sso\Contracts\ReinitiatingDriver;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Correlation;
use SineMacula\Laravel\Sso\Protocols\Enums\CorrelationKind;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;

/**
 * The `correlation` step (SSO-5.6): the connection's driver reads which
 * authorisation request the response answers, and validates nothing, outside
 * any transaction.
 *
 * A solicited response goes on with its correlation. A response nothing in it
 * correlates is refused with `request_unknown`, with no trusted redirect target
 * (SSO-5.7). An unsolicited response is handed, with its correlation, to
 * IdP-initiated re-initiation (SSO-5.8, `Completion\UnsolicitedReinitiation`)
 * when the connection's driver re-initiates (`Contracts\ReinitiatingDriver`,
 * the SAML driver): it consumes no request and runs no further step. A driver
 * that does not re-initiate has its unsolicited response refused with
 * `request_unknown`, as an uncorrelated one.
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
        $driver      = $this->protocols->protocol($connection->protocol);
        $correlation = $driver->correlate($connection, $state->request);

        return match ($correlation->kind) {
            CorrelationKind::SOLICITED    => StageOutcome::proceed($state->withCorrelation($correlation)),
            CorrelationKind::UNSOLICITED  => self::unsolicited($state, $correlation, $driver),
            CorrelationKind::UNCORRELATED => StageOutcome::refuse($state, FailureReason::REQUEST_UNKNOWN),
        };
    }

    /**
     * Hand an unsolicited response to re-initiation, with its correlation, when
     * the driver re-initiates; refuse it with `request_unknown`, from the state
     * it arrived in, otherwise.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  \SineMacula\Laravel\Sso\Protocols\Correlation  $correlation
     * @param  \SineMacula\Laravel\Sso\Contracts\ProtocolDriver  $driver
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     */
    private static function unsolicited(CompletionState $state, Correlation $correlation, ProtocolDriver $driver): StageOutcome
    {
        if (!$driver instanceof ReinitiatingDriver) {
            return StageOutcome::refuse($state, FailureReason::REQUEST_UNKNOWN);
        }

        return StageOutcome::reinitiate($state->withCorrelation($correlation));
    }
}
