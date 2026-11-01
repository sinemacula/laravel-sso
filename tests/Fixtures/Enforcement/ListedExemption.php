<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Enforcement;

use SineMacula\Laravel\Sso\Contracts\EnforcementExemption;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * An exemption contract that exempts the identities it lists, as a break-glass
 * administrator would be, and nobody else. It records each question, so a test
 * proves whether the contract was asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-type Question array{
 *     policy: \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy,
 *     application: string,
 *     identity: \SineMacula\Laravel\Sso\Identities\IdentityReference
 * }
 *
 * @internal
 */
final class ListedExemption implements EnforcementExemption
{
    /** @var list<Question> Each question, in order. */
    private array $asked = [];

    /**
     * Constructor.
     *
     * @param  list<\SineMacula\Laravel\Sso\Identities\IdentityReference>  $exempt
     */
    public function __construct(

        /** The identities exempt from every tenant's enforcement. */
        private readonly array $exempt = [],
    ) {}

    /**
     * Exempt when the identity is listed, byte for byte.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \SineMacula\Laravel\Sso\Enforcement\Enums\ExemptionOutcome
     */
    #[\Override]
    public function exemption(EnforcementPolicy $policy, string $application, IdentityReference $identity): ExemptionOutcome
    {
        $this->asked[] = ['policy' => $policy, 'application' => $application, 'identity' => $identity];

        foreach ($this->exempt as $listed) {
            if ($listed->is($identity)) {
                return ExemptionOutcome::EXEMPT;
            }
        }

        return ExemptionOutcome::NOT_EXEMPT;
    }

    /**
     * Each question, in order.
     *
     * @return list<Question>
     */
    public function asked(): array
    {
        return $this->asked;
    }
}
