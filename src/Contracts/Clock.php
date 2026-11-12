<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use Carbon\CarbonImmutable;
use Psr\Clock\ClockInterface;

/**
 * The one clock every time check in the package reads.
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
