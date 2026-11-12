<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Clock;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Date;
use SineMacula\Laravel\Sso\Contracts\Clock;

/**
 * The default clock: Laravel's `Date` facade, so it follows the test clock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SystemClock implements Clock
{
    /**
     * The current instant as a `CarbonImmutable`, whatever the date factory
     * makes.
     *
     * @return \Carbon\CarbonImmutable
     */
    #[\Override]
    public function now(): CarbonImmutable
    {
        return CarbonImmutable::instance(Date::now());
    }
}
