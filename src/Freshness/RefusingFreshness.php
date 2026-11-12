<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Freshness;

use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\Caller;

/**
 * The default freshness contract: always `stale`, until the application binds
 * one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RefusingFreshness implements Freshness
{
    /**
     * Refuse the operation.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @param  int  $maxAgeSeconds
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome
     */
    #[\Override]
    public function check(FreshnessOperation $operation, int $maxAgeSeconds, ?Caller $caller): FreshnessOutcome
    {
        unset($operation, $maxAgeSeconds, $caller);

        return FreshnessOutcome::STALE;
    }
}
