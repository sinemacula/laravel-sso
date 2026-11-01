<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Freshness;

use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;

/**
 * A freshness contract for the management helpers' tests: it answers the
 * outcome it is set to, `fresh` unless told otherwise, and records each
 * operation it is asked about with the maximum age it was asked with, in order,
 * so a test asserts exactly what a helper asked. A test that needs the state to
 * change between a helper's first read and its transaction sets `onCheck`,
 * which runs once, as the contract is next asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingFreshness implements Freshness
{
    /** @var ?\Closure(): void What runs as the contract is next asked, once, before it answers. */
    public ?\Closure $onCheck = null;

    /** @var list<array{0: \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation, 1: int}> Each operation asked about, with its maximum age, in order. */
    private array $asked = [];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome  $outcome
     */
    public function __construct(

        /** What every check answers. */
        private FreshnessOutcome $outcome = FreshnessOutcome::FRESH,
    ) {}

    /**
     * Record the operation and its maximum age, run `onCheck` once if it is
     * set, and answer the outcome set.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @param  int  $maxAgeSeconds
     * @return \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome
     */
    #[\Override]
    public function check(FreshnessOperation $operation, int $maxAgeSeconds): FreshnessOutcome
    {
        $this->asked[] = [$operation, $maxAgeSeconds];

        $onCheck       = $this->onCheck;
        $this->onCheck = null;

        if ($onCheck !== null) {
            $onCheck();
        }

        return $this->outcome;
    }

    /**
     * Answer the outcome given from now on.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome  $outcome
     * @return void
     */
    public function answer(FreshnessOutcome $outcome): void
    {
        $this->outcome = $outcome;
    }

    /**
     * Each operation asked about since the last reset, with its maximum age, in
     * order.
     *
     * @return list<array{0: \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation, 1: int}>
     */
    public function asked(): array
    {
        return $this->asked;
    }

    /**
     * Each operation asked about since the last reset, in order.
     *
     * @return list<\SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation>
     */
    public function operations(): array
    {
        return array_map(static fn (array $asked): FreshnessOperation => $asked[0], $this->asked);
    }

    /**
     * Forget what was asked.
     *
     * @return void
     */
    public function reset(): void
    {
        $this->asked = [];
    }
}
