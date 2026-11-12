<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\Caller;

/**
 * Decides whether a caller authenticated recently enough for an operation that
 * could widen, redirect or destroy access.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Freshness
{
    /**
     * Judge the caller, not the current request; answer `stale` for no caller
     * or one that cannot be judged, and never `fresh` when unsure.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @param  int  $maxAgeSeconds
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome
     */
    public function check(FreshnessOperation $operation, int $maxAgeSeconds, ?Caller $caller): FreshnessOutcome;
}
