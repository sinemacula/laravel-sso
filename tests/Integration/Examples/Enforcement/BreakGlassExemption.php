<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Enforcement;

use SineMacula\Laravel\Sso\Contracts\EnforcementExemption;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The example application's exemption (SSO-4.4): one break-glass administrator
 * may have a session in an enforcing tenant without a connection that satisfies
 * its rule, for when the identity provider is down; nobody else may.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class BreakGlassExemption implements EnforcementExemption
{
    /** @var string The break-glass administrator's user id. */
    public const string ADMINISTRATOR = 'break-glass-1';

    /**
     * Whether the identity is the break-glass administrator, in every tenant
     * and on every application.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome
     */
    #[\Override]
    public function exemption(EnforcementPolicy $policy, string $application, IdentityReference $identity): ExemptionOutcome
    {
        unset($policy, $application);

        return $identity->is(new IdentityReference('App\Models\User', self::ADMINISTRATOR)) ? ExemptionOutcome::EXEMPT : ExemptionOutcome::NOT_EXEMPT;
    }
}
