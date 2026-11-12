<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Freshness;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\Caller;

/**
 * Asks the bound freshness contract about an operation before it writes.
 *
 * The contract is resolved on each call, so a per-request binding is honoured.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FreshnessGate
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Sso\Freshness\MaximumAges  $maximumAges
     */
    public function __construct(

        /** The container the freshness contract is resolved from on each call. */
        private Container $container,

        /** The maximum age each operation requires. */
        private MaximumAges $maximumAges,
    ) {}

    /**
     * Ask the freshness contract about the operation for the caller.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function check(FreshnessOperation $operation, ?Caller $caller): FreshnessOutcome
    {
        $maxAge = $this->maximumAges->for($operation);

        return $this->container->make(Freshness::class)->check($operation, $maxAge, $caller);
    }

    /**
     * Ask about each distinct operation in order, stopping at the first
     * `stale`.
     *
     * @param  list<\SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation>  $operations
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function checkAll(array $operations, ?Caller $caller): FreshnessOutcome
    {
        $asked = [];

        foreach ($operations as $operation) {

            if (isset($asked[$operation->value])) {
                continue;
            }

            $asked[$operation->value] = true;

            if (!$this->check($operation, $caller)->isFresh()) {
                return FreshnessOutcome::STALE;
            }
        }

        return FreshnessOutcome::FRESH;
    }
}
