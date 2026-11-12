<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Decides whether an identity may bypass an enforcing tenant's connections, for
 * example a break-glass administrator.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EnforcementExemption
{
    /**
     * Never answer `exempt` when unsure; let an error propagate instead.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome
     */
    public function exemption(EnforcementPolicy $policy, string $application, IdentityReference $identity): ExemptionOutcome;
}
