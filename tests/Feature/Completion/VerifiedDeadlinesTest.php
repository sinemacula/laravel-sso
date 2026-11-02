<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\VerifiedDeadlines;
use SineMacula\Laravel\Sso\Contracts\Clock;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for when a verified response stops being valid: the configured
 * age from now, or its request's expiry when that comes first; and that the
 * deadline passes at its instant, not after it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerifiedDeadlines::class)]
final class VerifiedDeadlinesTest extends TestCase
{
    /** @var string The instant the clock reads. */
    private const string NOW = '2026-11-01T09:30:00+00:00';

    /**
     * Bind a fixed clock and a maximum age of a minute.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock(self::NOW));

        config()->set('sso.linking.verified_result_max_age_seconds', 60);
    }

    /**
     * With no request's expiry the configured age decides; with one the earlier
     * of the two does.
     *
     * @return void
     */
    public function testTheDeadlineIsTheEarlierOfTheAgeAndTheRequestsExpiry(): void
    {
        $now       = CarbonImmutable::parse(self::NOW);
        $deadlines = app(VerifiedDeadlines::class);

        self::assertSame('2026-11-01T09:31:00+00:00', $deadlines->until(null)->toIso8601String());
        self::assertSame('2026-11-01T09:31:00+00:00', $deadlines->until($now->addHour())->toIso8601String());
        self::assertSame('2026-11-01T09:30:30+00:00', $deadlines->until($now->addSeconds(30))->toIso8601String());
    }

    /**
     * A deadline has passed at its instant and after it, and not before; a
     * state with none has nothing to judge.
     *
     * @return void
     */
    public function testADeadlinePassesAtItsInstant(): void
    {
        $now       = CarbonImmutable::parse(self::NOW);
        $deadlines = app(VerifiedDeadlines::class);

        self::assertTrue($deadlines->hasPassed($now->subSecond()));
        self::assertTrue($deadlines->hasPassed($now));
        self::assertFalse($deadlines->hasPassed($now->addSecond()));
        self::assertFalse($deadlines->hasPassed(null));
    }
}
