<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Enforcement;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Sso\Administration\EnforcementEvents;
use SineMacula\Laravel\Sso\Contracts\EnforcementExemption;
use SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Asks the exemption contract about a session that does not satisfy its
 * tenant's enforcement, and reports each exemption granted.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExemptionGate
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Sso\Administration\EnforcementEvents  $events
     */
    public function __construct(

        /** Resolves the exemption contract on each call. */
        private Container $container,

        /** Reports each exemption granted. */
        private EnforcementEvents $events,
    ) {}

    /**
     * Whether the identity may have a session without a satisfying connection,
     * reporting an exemption granted.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?string  $sessionId
     * @return \SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function admit(EnforcementPolicy $policy, string $application, IdentityReference $identity, ClientContext $client, ?string $sessionId = null): ExemptionOutcome
    {
        $outcome = $this->judge($policy, $application, $identity);

        if ($outcome->isExempt()) {
            $this->events->exemptionUsed($policy, $application, $identity, $client, $sessionId);
        }

        return $outcome;
    }

    /**
     * As `admit()` judges, reporting nothing: for a session judged again whose
     * exemption was reported when it was admitted.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function judge(EnforcementPolicy $policy, string $application, IdentityReference $identity): ExemptionOutcome
    {
        self::assertApplication($application);

        if (!$policy->isRequired()) {
            return ExemptionOutcome::NOT_EXEMPT;
        }

        return $this->container->make(EnforcementExemption::class)->exemption($policy, $application, $identity);
    }

    /**
     * Assert the application an exemption is asked for is named.
     *
     * @param  string  $application
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertApplication(string $application): void
    {
        if ($application === '') {
            throw new \InvalidArgumentException('An exemption is asked for an application.');
        }
    }
}
