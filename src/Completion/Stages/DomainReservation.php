<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Stages;

use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\StageOutcome;
use SineMacula\Laravel\Sso\Contracts\CompletionStage;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\DomainLinkEligibility;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkStorageBinding;
use SineMacula\Laravel\Sso\Links\LinkSubject;

/**
 * The `domain_reservation` step: reserves a link for an unlinked `sign_in` with
 * exactly one eligible identity, under that identity's guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-import-type Eligible from \SineMacula\Laravel\Sso\Linking\DomainLinkEligibility
 */
final readonly class DomainReservation implements CompletionStage
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Linking\DomainLinkEligibility  $eligibility
     * @param  \SineMacula\Laravel\Sso\Links\LinkStorageBinding  $storage
     */
    public function __construct(

        /** Judges the conditions a reservation is made under. */
        private DomainLinkEligibility $eligibility,

        /** Writes the reservation. */
        private LinkStorageBinding $storage,
    ) {}

    /**
     * Reserve a link for an eligible result, refusing what the plain reads
     * before the locks did not see.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     *
     * @throws \LogicException
     */
    #[\Override]
    public function run(CompletionState $state): StageOutcome
    {
        if (($state->resolution?->isAbsent() ?? false) && ($state->linkingDiscovery->subjectHeld ?? false)) {
            return StageOutcome::refuse($state, FailureReason::LINK_CHANGED);
        }

        $eligible = $this->eligibility->atCompletion($state);

        if ($eligible === null) {
            return StageOutcome::proceed($state);
        }

        return self::isGuarded($state, $eligible['identity']) ? $this->reserved($state, $eligible) : StageOutcome::refuse($state, FailureReason::RESERVATION_INVALID);
    }

    /**
     * Whether the identity is the one whose guard the completion holds.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return bool
     */
    private static function isGuarded(CompletionState $state, IdentityReference $identity): bool
    {
        return $state->linkingDiscovery?->identity?->is($identity) ?? false;
    }

    /**
     * Write the reservation, and go on with its candidate.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  Eligible  $eligible
     * @return \SineMacula\Laravel\Sso\Completion\StageOutcome
     *
     * @throws \LogicException
     * @throws \Throwable
     */
    private function reserved(CompletionState $state, array $eligible): StageOutcome
    {
        $reservations = $this->storage->require('Linking by a verified domain')->reservations();
        $candidate    = $reservations->reserve($eligible['connection'], LinkSubject::of($eligible['result']), $eligible['identity'], $eligible['terms']);

        return StageOutcome::proceed($state->withResolution(LinkResolution::absent(), $candidate));
    }
}
