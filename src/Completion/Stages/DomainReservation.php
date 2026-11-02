<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Stages;

use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Linking\DomainLinkEligibility;
use SineMacula\Laravel\Sso\Links\LinkReservations;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkSubject;

/**
 * The `domain_reservation` step (SSO-8.8): an unlinked `sign_in` result that
 * `Linking\DomainLinkEligibility` finds exactly one eligible identity for
 * reserves a link for it, atomically under the link store's uniqueness and
 * limit, bound to the request, the identity matched and the linking email, and
 * to the handoff the `handoff_issuance` step issues in this same transaction.
 * The candidate goes on with the state, apart from the resolved identity, and
 * such a result is never provisioned. It never refuses: a result it does not
 * reserve for goes on unlinked.
 *
 * It holds the eligibility and the reservations, neither of which keeps
 * anything of one completion for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DomainReservation implements CompletionStage
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Linking\DomainLinkEligibility  $eligibility
     * @param  \SineMacula\Laravel\Sso\Links\LinkReservations  $reservations
     */
    public function __construct(

        /** Judges the conditions a reservation is made under. */
        private DomainLinkEligibility $eligibility,

        /** Writes the reservation. */
        private LinkReservations $reservations,
    ) {}

    /**
     * Reserve a link for an eligible result, and go on either way.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     *
     * @throws \LogicException
     */
    #[\Override]
    public function run(CompletionState $state): StageOutcome
    {
        $eligible = $this->eligibility->atCompletion($state);

        if ($eligible === null) {
            return StageOutcome::proceed($state);
        }

        $candidate = $this->reservations->reserve($eligible['connection'], LinkSubject::of($eligible['result']), $eligible['identity'], $eligible['terms']);

        return StageOutcome::proceed($state->withResolution(LinkResolution::absent(), $candidate));
    }
}
