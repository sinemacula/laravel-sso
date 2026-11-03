<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Clock;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Date;
use SineMacula\Laravel\Sso\Contracts\Clock;

/**
 * The example application's own clock (SSO-11.13): Laravel's current instant,
 * always in UTC whatever the application's timezone, read afresh on every call
 * so it holds no instant from one request or job to the next.
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
