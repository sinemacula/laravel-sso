<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Enforcement;

use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Enforcement\ExemptionGate;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The example application's tenant authentication policy, asked at sign-in, on
 * every switch and on refresh.
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
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return bool
     */
    public function admits(UserSession $session, ClientContext $client): bool
    {
        // @snippet-start enforcement-policy
        $policy = app(Enforcement::class)->policy($session->tenant_id, 'web');

        // Recheck the session once the version moves on
        $session->update(['enforcement_version' => $policy->version]);

        // A session established without SSO records no connection, which
        // satisfies no rule
        if ($policy->isRequired() && !$policy->isSatisfiedBy($session->sso_connection_id ?? '')) {
            return $this->isExempt($policy, $session, $client); // refused, unless the identity is exempt (below)
        }

        return true;
        // @snippet-end enforcement-policy
    }

    /**
     * Whether the session's identity is exempt, asked through the gate that
     * reports each exemption.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
     * @param  \Tests\Integration\Examples\Enforcement\UserSession  $session
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return bool
     */
    private function isExempt(EnforcementPolicy $policy, UserSession $session, ClientContext $client): bool
    {
        // @snippet-start enforcement-exemption
        $identity = new IdentityReference($session->user_type, $session->user_id);

        $outcome = app(ExemptionGate::class)->admit($policy, 'web', $identity, $client, $session->id);

        return $outcome->isExempt();
        // @snippet-end enforcement-exemption
    }
}
