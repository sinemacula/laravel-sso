<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Freshness;

use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\Caller;

/**
 * The default freshness contract: it answers `stale` for every operation, so no
 * operation SSO-2.12 lists writes until the application binds a contract that
 * can judge its callers (SSO-2.12). It holds nothing, and fails closed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RefusingFreshness implements Freshness
{
    /**
     * Refuse the operation, whatever its maximum age and whoever the caller.
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
