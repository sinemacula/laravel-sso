<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Rules;

use SineMacula\Laravel\Sso\Clock\ClockSkew;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkResolutionStatus;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;

/**
 * What a `reauthenticate` requires at completion: the flow's identity and a
 * plausible authentication time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ReauthenticationRules
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** The clock a future authentication is judged against. */
        private Clock $clock,
    ) {}

    /**
     * Why the state may not go on as a `reauthenticate`, or `null` when it may.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     *
     * @throws \LogicException
     */
    public function refusal(CompletionState $state): ?FailureReason
    {
        $request  = $state->authorizationRequest ?? throw new \LogicException('A reauthentication is checked once its request is consumed.');
        $identity = IdentityReference::fromColumns($request->identity_type, $request->identity_id)
            ?? throw new \LogicException('A reauthenticate flow names the identity it was started for.');

        return self::linkRefusal($state->resolution, $identity) ?? $this->authenticationRefusal($state, $request);
    }

    /**
     * Why the resolved link is not the identity's, or `null`.
     *
     * @param  ?\SineMacula\Laravel\Sso\Links\LinkResolution  $resolution
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private static function linkRefusal(?LinkResolution $resolution, IdentityReference $identity): ?FailureReason
    {
        return match ($resolution?->status) {
            LinkResolutionStatus::SUSPENDED     => FailureReason::LINK_SUSPENDED,
            LinkResolutionStatus::SCOPE_UNKNOWN => FailureReason::PRINCIPAL_SCOPE_UNKNOWN,
            LinkResolutionStatus::LINKED        => $resolution->isHeldBy($identity) ? null : FailureReason::IDENTITY_MISMATCH,
            default                             => FailureReason::IDENTITY_MISMATCH,
        };
    }

    /**
     * Why the authentication time cannot renew a session, or `null`; the
     * built-in drivers check this already, a driver added by extend() may not.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @param  \SineMacula\Laravel\Sso\Models\AuthorizationRequest  $request
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     *
     * @throws \InvalidArgumentException
     */
    private function authenticationRefusal(CompletionState $state, AuthorizationRequest $request): ?FailureReason
    {
        $authenticatedAt = $state->result?->authenticationContext->authenticatedAt;
        $skew            = ClockSkew::seconds();

        return match (true) {
            $authenticatedAt === null                                  => FailureReason::AUTHENTICATION_EXPIRED,
            $authenticatedAt > $this->clock->now()->addSeconds($skew)  => FailureReason::ASSERTION_EXPIRED,
            $authenticatedAt < $request->created_at->subSeconds($skew) => FailureReason::AUTHENTICATION_EXPIRED,
            default                                                    => null,
        };
    }
}
