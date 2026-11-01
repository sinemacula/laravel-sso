<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use Carbon\CarbonImmutable;
use Psr\Clock\ClockInterface;

/**
 * Clock contract: the one clock every time check of the package reads
 * (SSO-11.13), so skew, expiry and maximum ages can be tested and an
 * application can bind its own.
 *
 * PSR-20 shaped, answering a `CarbonImmutable` so callers compare and add
 * without converting. The default reads Laravel's `Date` facade, so a test that
 * freezes Laravel's clock freezes the package's too; `Testing\FrozenClock`
 * holds one instant until it is moved. An implementation holds no state from
 * one request to the next beyond what a test sets (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Clock extends ClockInterface
{
    /**
     * The current instant.
     *
     * @return \Carbon\CarbonImmutable
     */
    #[\Override]
    public function now(): CarbonImmutable;
}
