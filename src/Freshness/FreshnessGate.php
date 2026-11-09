<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Freshness;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\Caller;

/**
 * What every operation SSO-2.12 lists calls before it writes: it reads the
 * operation's maximum age from `MaximumAges` and asks the bound `Freshness`
 * contract with the operation's stable name, that age and the caller the action
 * is taken for, `null` when there is none (SSO-2.12).
 *
 * The contract is resolved from the container on each call, never held, so a
 * binding made per request or swapped in a test is the one asked, and nothing
 * of one caller is kept for the next (SSO-11.2). A malformed maximum age fails
 * closed with an `InvalidArgumentException` before the contract is asked.
 *
 * An operation that is several of the listed ones at once (a change that is a
 * trust change and turns IdP-initiated sign-in on, say) asks `checkAll()`,
 * which asks each operation once, in the order given, and stops at the first
 * `stale`.
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
     * Ask the freshness contract about the operation, with its maximum age, for
     * the caller.
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
     * Ask about each operation once, in the order given, and answer `stale` at
     * the first that is; `fresh` when every one is, or none is given. Each is
     * asked for the caller.
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
