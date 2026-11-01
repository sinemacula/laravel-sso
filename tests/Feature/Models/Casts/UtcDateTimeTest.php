<?php

declare(strict_types = 1);

namespace Tests\Feature\Models\Casts;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\RateLimit;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use Tests\Concerns\RunsInTimezone;
use Tests\TestCase;

/**
 * Feature tests for the UTC time cast the package's models use: an instant or a
 * Unix time is written as UTC wall-clock seconds, and a stored value read back
 * as that instant, whatever the application timezone, so the hour a
 * daylight-saving fall-back repeats names each instant once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UtcDateTime::class)]
final class UtcDateTimeTest extends TestCase
{
    use RunsInTimezone;

    /**
     * An instant in any timezone, and a Unix time, are formatted in UTC to the
     * whole second, whatever the application timezone.
     *
     * @return void
     */
    public function testFormatsInUtc(): void
    {
        $this->inTimezone('Europe/London', static function (): void {
            $model = new SingleUseKey;

            self::assertSame('2026-10-25 00:40:00', UtcDateTime::format($model, CarbonImmutable::parse('2026-10-25T01:40:00.75+01:00')));
            self::assertSame('2026-10-25 01:30:00', UtcDateTime::format($model, CarbonImmutable::parse('2026-10-25T01:30:00+00:00')));
            self::assertSame('2026-10-25 01:00:00', UtcDateTime::format($model, CarbonImmutable::parse('2026-10-25T01:00:00Z')->getTimestamp()));
        });
    }

    /**
     * A stored value is read as the instant it names in UTC, in a timezone
     * whose wall clock repeats that hour; `null` stays `null`.
     *
     * @return void
     */
    public function testReadsAStoredValueAsAUtcInstant(): void
    {
        $this->inTimezone('Europe/London', static function (): void {
            $cast  = new UtcDateTime;
            $model = new RateLimit;
            $read  = $cast->get($model, 'window_ends_at', '2026-10-25 01:00:00', []);

            self::assertInstanceOf(CarbonImmutable::class, $read);
            self::assertSame(CarbonImmutable::parse('2026-10-25T01:00:00Z')->getTimestamp(), $read->getTimestamp());
            self::assertNull($cast->get($model, 'window_ends_at', null, []));
        });
    }

    /**
     * An instant or a Unix time is stored as UTC seconds, `null` as `null`, and
     * anything else is refused.
     *
     * @return void
     */
    public function testStoresAnInstantOrAUnixTime(): void
    {
        $cast  = new UtcDateTime;
        $model = new SingleUseKey;

        self::assertSame('2026-10-31 12:00:00', $cast->set($model, 'expires_at', CarbonImmutable::parse('2026-10-31T21:00:00+09:00'), []));
        self::assertSame('2026-10-31 12:00:00', $cast->set($model, 'expires_at', CarbonImmutable::parse('2026-10-31T12:00:00Z')->getTimestamp(), []));
        self::assertNull($cast->set($model, 'expires_at', null, []));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`expires_at` must be set to an instant or a Unix time.');

        $cast->set($model, 'expires_at', '2026-10-31 12:00:00', []);
    }

    /**
     * A stored value that is not text is refused rather than read as a time.
     *
     * @return void
     */
    public function testRefusesAStoredValueThatIsNotText(): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('The stored value of `expires_at` is not a time.');

        (new UtcDateTime)->get(new SingleUseKey, 'expires_at', 1793000000, []);
    }

    /**
     * An instant set on a model reads back as the `CarbonImmutable` in UTC that
     * the stored value names, whatever kind of instant or zone it was set with,
     * never as the object it was given.
     *
     * @return void
     */
    public function testAnInstantSetOnAModelReadsBackInUtc(): void
    {
        $model = new SingleUseKey;

        $model->setAttribute('expires_at', new \DateTimeImmutable('2026-10-31T21:00:00+09:00'));

        self::assertInstanceOf(CarbonImmutable::class, $model->expires_at);
        self::assertSame('2026-10-31T12:00:00+00:00', $model->expires_at->format(DATE_ATOM));
    }
}
