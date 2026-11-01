<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Clock;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Date;
use SineMacula\Laravel\Sso\Contracts\Clock;

/**
 * The default clock: the current instant as Laravel's `Date` facade gives it,
 * read afresh on every call (SSO-11.13).
 *
 * It follows Laravel's test clock, so `Carbon::setTestNow()`,
 * `Date::setTestNow()` and a test's `travelTo()` or `freezeTime()` move the
 * package's clock with the application's. Whatever class the application's date
 * factory makes (`Carbon`, `CarbonImmutable` or another `DateTimeInterface`),
 * the instant is answered as a `CarbonImmutable` to the microsecond, in the
 * zone the factory gave it.
 *
 * It holds nothing, so it is shared as a singleton and is safe under Octane and
 * in a queue worker: no instant outlives the call that read it (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SystemClock implements Clock
{
    /**
     * The current instant, as Laravel's date factory gives it.
     *
     * @return \Carbon\CarbonImmutable
     */
    #[\Override]
    public function now(): CarbonImmutable
    {
        return CarbonImmutable::instance(Date::now());
    }
}
