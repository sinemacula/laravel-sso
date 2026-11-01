<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Exemption contract (SSO-4.4): whether an identity may be signed in to an
 * enforcing tenant, on an application, without one of the connections that
 * satisfy its enforcement; a break-glass administrator for when the identity
 * provider is down, say.
 *
 * The default, `Enforcement\NoExemptions`, exempts nobody. A session
 * established under an exemption is reported (`Events\ExemptionUsed`) by the
 * package's helper that asks this contract, never by the contract itself. An
 * implementation answers from current state on each call and keeps nothing of
 * one call for the next (SSO-11.2); an error it cannot answer through
 * propagates, and it never answers `exempt` when it cannot tell.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EnforcementExemption
{
    /**
     * Whether the identity is exempt from the enforcement, on the application.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome
     */
    public function exemption(EnforcementPolicy $policy, string $application, IdentityReference $identity): ExemptionOutcome;
}
