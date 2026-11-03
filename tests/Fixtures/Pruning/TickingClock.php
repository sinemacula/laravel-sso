<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Pruning;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\Clock;

/**
 * A clock that moves on the seconds given each time it is read, counting its
 * readings, so a test can show how many an operation takes and what it does
 * with each.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TickingClock implements Clock
{
    /** @var int How many times the clock has been read. */
    public int $reads = 0;

    /** @var \Carbon\CarbonImmutable The instant the next reading answers. */
    private CarbonImmutable $next;

    /**
     * Constructor.
     *
     * @param  string  $start
     * @param  int  $seconds
     */
    public function __construct(

        // Not promoted: the first reading, which readings move on from
        string $start,

        /** How far each reading moves on. */
        private readonly int $seconds,
    ) {
        $this->next = CarbonImmutable::parse($start);
    }

    /**
     * The next instant.
     *
     * @return \Carbon\CarbonImmutable
     */
    #[\Override]
    public function now(): CarbonImmutable
    {
        $now = $this->next;

        $this->next = $now->addSeconds($this->seconds);

        $this->reads++;

        return $now;
    }
}
