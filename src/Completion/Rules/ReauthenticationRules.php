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
 * What a `reauthenticate` requires at completion (SSO-5.10), the first refusal
 * answering:
 *
 * 1. the result must resolve to the identity the request was started for: a
 *    suspended link blocks reauthentication (`link_suspended`), and a subject
 *    resolving to nobody, to a reservation or to another identity is
 *    `identity_mismatch`, naming nobody. Whether the link is the exact one that
 *    established the session is judged at redemption, under the session's lock
 *    (`Handoffs\Redemption\ReauthenticationBranch`);
 * 2. the result must state when the provider authenticated, no earlier than the
 *    request's start less the skew, or `authentication_expired`, and no later
 *    than now plus the skew, or `assertion_expired`.
 *
 * The OpenID Connect and SAML drivers have refused such a response already
 * (`Protocols\Oidc\IdTokens\AuthenticationTimeRules`,
 * `Protocols\Saml2\Validation\AuthenticationRules`). The second rule is what
 * keeps SSO-5.10 true of any other driver registered through
 * `Protocols\ProtocolManager::extend()`, whose claims nothing else judges: a
 * code issued from such a result would renew a session from an authentication
 * that never happened, or that happened before the flow started.
 *
 * It holds the clock, which keeps nothing of one completion for the next
 * (SSO-11.2), and reads the skew on each call.
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
     * Why the link as resolved is not the identity's to reauthenticate through,
     * or `null`.
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
     * Why the provider's authentication time is not one this flow can renew a
     * session from, or `null`.
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
