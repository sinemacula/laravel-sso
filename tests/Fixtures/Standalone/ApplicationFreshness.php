<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Standalone;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;

/**
 * An application's freshness contract, which judges its caller as a real one
 * does: `fresh` only when the caller authenticated no more than the maximum age
 * ago, by the package's clock, and `stale` otherwise, with no caller included.
 * `Testing\FakeFreshness` answers what it is told; this one reads a time, so a
 * test can pin the boundary of the age the package asks with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ApplicationFreshness implements Freshness
{
    /** @var ?\Carbon\CarbonImmutable When the caller last authenticated; none when there is no caller. */
    public ?CarbonImmutable $authenticatedAt = null;

    /** @var list<array{0: \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation, 1: int}> Each operation asked about, with its maximum age, in order. */
    public array $asked = [];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** The clock the caller's age is read from. */
        private readonly Clock $clock,
    ) {}

    /**
     * Record the question, and judge the caller.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @param  int  $maxAgeSeconds
     * @return \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome
     */
    #[\Override]
    public function check(FreshnessOperation $operation, int $maxAgeSeconds): FreshnessOutcome
    {
        $this->asked[] = [$operation, $maxAgeSeconds];

        if ($this->authenticatedAt === null || $this->authenticatedAt->addSeconds($maxAgeSeconds) < $this->clock->now()) {
            return FreshnessOutcome::STALE;
        }

        return FreshnessOutcome::FRESH;
    }
}
