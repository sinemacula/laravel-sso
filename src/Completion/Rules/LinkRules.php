<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Rules;

use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkResolution;

/**
 * What a `link` requires at completion (SSO-5.11, SSO-8.5): the identity it was
 * started for may link through the connection (`link_ineligible`); the subject
 * is held by no live reservation, which is busy rather than converted
 * (`link_reserved`); and no other identity holds it, active or suspended
 * (`subject_already_linked`, naming nobody). A subject suspended on this same
 * identity goes on, so the person can confirm it (SSO-8.8).
 *
 * It holds the eligibility contract, which keeps nothing of one completion for
 * the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LinkRules
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\LinkEligibility  $eligibility
     */
    public function __construct(

        /** Whether the identity may link through the connection. */
        private LinkEligibility $eligibility,
    ) {}

    /**
     * Why the state may not go on as a `link`, or `null` when it may.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     *
     * @throws \LogicException
     */
    public function refusal(CompletionState $state): ?FailureReason
    {
        $request    = $state->authorizationRequest ?? throw new \LogicException('A link is checked once its request is consumed.');
        $connection = $state->connection           ?? throw new \LogicException('A link is checked once its connection is read.');
        $identity   = IdentityReference::fromColumns($request->identity_type, $request->identity_id);

        if ($identity === null) {
            throw new \LogicException('A link flow names the identity it was started for.');
        }

        return $this->eligibility->judge($identity, $connection)->isEligible() ? self::subjectRefusal($state->resolution, $identity) : FailureReason::LINK_INELIGIBLE;
    }

    /**
     * Why the subject may not be linked to the identity, as it resolved.
     *
     * @param  ?\SineMacula\Laravel\Sso\Links\LinkResolution  $resolution
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private static function subjectRefusal(?LinkResolution $resolution, IdentityReference $identity): ?FailureReason
    {
        if ($resolution === null) {
            return null;
        }

        return match (true) {
            $resolution->isReserved()                                         => FailureReason::LINK_RESERVED,
            $resolution->holder !== null && !$resolution->isHeldBy($identity) => FailureReason::SUBJECT_ALREADY_LINKED,
            default                                                           => null,
        };
    }
}
