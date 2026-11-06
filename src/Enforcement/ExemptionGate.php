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
 * What an adapter calls when a session active in an enforcing tenant would
 * otherwise be refused, because it was not established through a connection
 * that satisfies the tenant's enforcement (SSO-4.4, SSO-9.3): it asks the
 * exemption contract whether the identity is exempt, and reports each exemption
 * it grants.
 *
 * A policy that requires nothing needs no exemption: the answer is
 * `not_exempt`, with nothing asked or reported, since there is nothing to be
 * exempt from. Otherwise `Contracts\EnforcementExemption`, resolved from the
 * container on each call, is asked; an `exempt` answer is reported once as
 * `Events\ExemptionUsed` (through `Administration\EnforcementEvents`, after the
 * transaction open on the storage connection commits, at once when none is) and
 * returned. An exception from the contract propagates: the gate never answers
 * `exempt` when it cannot tell.
 *
 * It takes the client the session is admitted for as an `Http\ClientContext`,
 * whose IP address and user agent `Events\ExemptionUsed` carries, and reads no
 * request. It holds the container and the reporter, neither of which keeps
 * anything of one call for the next (SSO-11.2). Resolve it from the container
 * per request.
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
     * Whether the identity may have a session in the policy's tenant, on the
     * application, without a satisfying connection; `exempt` is reported, with
     * the client and the session's id when the caller has one.
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
        self::assertApplication($application);

        if (!$policy->isRequired()) {
            return ExemptionOutcome::NOT_EXEMPT;
        }

        $outcome = $this->container->make(EnforcementExemption::class)->exemption($policy, $application, $identity);

        if ($outcome->isExempt()) {
            $this->events->exemptionUsed($policy, $application, $identity, $client, $sessionId);
        }

        return $outcome;
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
