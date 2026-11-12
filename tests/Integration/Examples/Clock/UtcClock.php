<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Clock;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Date;
use SineMacula\Laravel\Sso\Contracts\Clock;

/**
 * The example application's clock: Laravel's current instant, in UTC.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class UtcClock implements Clock
{
    /**
     * The current instant, in UTC.
     *
     * @return \Carbon\CarbonImmutable
     */
    #[\Override]
    public function now(): CarbonImmutable
    {
        return CarbonImmutable::instance(Date::now())->utc();
    }
}
