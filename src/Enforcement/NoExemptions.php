<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement;

use SineMacula\Laravel\Sso\Contracts\EnforcementExemption;
use SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Default exemption contract: nobody is exempt from a tenant's enforcement.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NoExemptions implements EnforcementExemption
{
    /**
     * Not exempt, whoever asks.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome
     */
    #[\Override]
    public function exemption(EnforcementPolicy $policy, string $application, IdentityReference $identity): ExemptionOutcome
    {
        return ExemptionOutcome::NOT_EXEMPT;
    }
}
