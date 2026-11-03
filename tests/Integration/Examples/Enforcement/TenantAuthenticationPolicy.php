<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Enforcement;

use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Enforcement\ExemptionGate;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The example application's tenant authentication policy (SSO-4.1, SSO-4.4,
 * SSO-4.6), asked at sign-in, on every switch and on refresh: a session active
 * in a tenant complies when the enforcement that applies to it requires
 * nothing, or it was established through a satisfying connection; otherwise it
 * is admitted only when its identity is exempt, which the exemption gate
 * reports. The session records the version it was judged against, so it is
 * judged again once the rule changes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenantAuthenticationPolicy
{
    /**
     * Whether the session may stay active in its tenant, on the application.
     *
     * @param  \Tests\Integration\Examples\Enforcement\UserSession  $session
     * @return bool
     */
    public function admits(UserSession $session): bool
    {
        // @snippet-start enforcement-policy
        $policy = app(Enforcement::class)->policy($session->tenant_id, 'web');

        // Recheck the session once the version moves on
        $session->update(['enforcement_version' => $policy->version]);

        // A session established without SSO records no connection, which
        // satisfies no rule
        if ($policy->isRequired() && !$policy->isSatisfiedBy($session->sso_connection_id ?? '')) {
            return $this->isExempt($policy, $session); // refused, unless the identity is exempt (below)
        }

        return true;
        // @snippet-end enforcement-policy
    }

    /**
     * Whether the session's identity is exempt from the enforcement, asked
     * through the gate, which reports each exemption it grants.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
     * @param  \Tests\Integration\Examples\Enforcement\UserSession  $session
     * @return bool
     */
    private function isExempt(EnforcementPolicy $policy, UserSession $session): bool
    {
        // @snippet-start enforcement-exemption
        $identity = new IdentityReference($session->user_type, $session->user_id);

        $outcome = app(ExemptionGate::class)->admit($policy, 'web', $identity, $session->id);

        return $outcome->isExempt();
        // @snippet-end enforcement-exemption
    }
}
