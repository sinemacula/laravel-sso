<?php

declare(strict_types = 1);

namespace Tests\Feature\Operations;

use Illuminate\Console\Scheduling\CallbackEvent;
use Illuminate\Console\Scheduling\Event as ScheduledEvent;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\Facades\Exceptions;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Operations\OperationsCheck;
use SineMacula\Laravel\Sso\Operations\OperationsSchedule;
use SineMacula\Laravel\Sso\Operations\OperationsSettings;
use Tests\Concerns\UsesUnreliableCache;
use Tests\TestCase;

/**
 * Feature tests for the operations schedule and its settings.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OperationsSchedule::class)]
#[CoversClass(OperationsSettings::class)]
#[CoversClass(OperationsCheck::class)]
final class OperationsScheduleTest extends TestCase
{
    use UsesUnreliableCache;

    /**
     * Turn the package on.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('sso.features.oidc', true);
    }

    /**
     * The four commands run on their default cadences on every server, with no
     * mutex.
     *
     * @return void
     */
    public function testRegistersEachCommandOnItsDefaultCadence(): void
    {
        $events = $this->registered();

        self::assertSame([
            'sso:prune'            => '0 * * * *',
            'sso:domains:recheck'  => '0 * * * *',
            'sso:metadata:refresh' => '*/5 * * * *',
            'sso:keys:expiring'    => '0 0 * * *',
        ], array_map(static fn (ScheduledEvent $event): string => $event->expression, $events));

        foreach ($events as $event) {
            self::assertFalse($event->withoutOverlapping);
            self::assertFalse($event->onOneServer);
        }
    }

    /**
     * Each cadence is configurable, and a task with none is left to the
     * application.
     *
     * @return void
     */
    public function testACadenceIsConfigurableOrLeftToTheApplication(): void
    {
        config()->set('sso.operations.cadence.prune', '15 3 * * *');
        config()->set('sso.operations.cadence.domain_recheck');
        config()->set('sso.operations.cadence.metadata_refresh', '');

        $events = $this->registered();

        self::assertSame(['sso:prune', 'sso:keys:expiring'], array_keys($events));
        self::assertSame('15 3 * * *', $events['sso:prune']->expression);
    }

    /**
     * Nothing is registered while the package is not in use.
     *
     * @return void
     */
    public function testRegistersNothingWhileThePackageIsNotInUse(): void
    {
        config()->set('sso.features.oidc', false);

        self::assertSame([], $this->registered());
    }

    /**
     * Opting in gives each task both mutexes, for as long as the setting says.
     *
     * @return void
     */
    public function testOptingInGivesEachTaskItsMutexes(): void
    {
        config()->set('sso.operations.cache_mutexes', true);
        config()->set('sso.operations.mutex_minutes', 15);

        foreach ($this->registered() as $event) {
            self::assertTrue($event->withoutOverlapping);
            self::assertTrue($event->onOneServer);
            self::assertSame(15, $event->expiresAt);
        }
    }

    /**
     * An opted-in mutex expires after an hour by default.
     *
     * @return void
     */
    public function testTheDefaultMutexExpiryIsAnHour(): void
    {
        config()->set('sso.operations.cache_mutexes', true);

        foreach ($this->registered() as $event) {
            self::assertSame(60, $event->expiresAt);
        }
    }

    /**
     * By default no task asks the cache whether it overlaps.
     *
     * @return void
     */
    public function testByDefaultNoTaskAsksTheCache(): void
    {
        $store = $this->breakTheCache();

        foreach ($this->registered() as $event) {
            self::assertFalse($event->shouldSkipDueToOverlapping());
        }

        self::assertSame(0, $store->calls);
    }

    /**
     * Rows of `[setting, value, message]`: what the settings refuse.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function provideRefusedValues(): iterable
    {
        $cadence = 'sso.operations.cadence.prune must be a cron expression, or null or empty for none.';

        yield 'a word' => ['cadence.prune', 'hourly', $cadence];
        yield 'too few fields' => ['cadence.prune', '* * *', $cadence];
        yield 'out of range' => ['cadence.prune', '61 * * * *', $cadence];
        yield 'a number' => ['cadence.prune', 5, $cadence];
        yield 'a switch that is not one' => ['cache_mutexes', 'perhaps', 'sso.operations.cache_mutexes must be true or false.'];
        yield 'no minutes' => ['mutex_minutes', 0, 'sso.operations.mutex_minutes must be an integer from 1 to 1440.'];
        yield 'too many minutes' => ['mutex_minutes', 1441, 'sso.operations.mutex_minutes must be an integer from 1 to 1440.'];
    }

    /**
     * A malformed setting fails the boot check.
     *
     * @param  string  $setting
     * @param  mixed  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedValues')]
    public function testRefusesAMalformedSetting(string $setting, mixed $value, string $message): void
    {
        config()->set("sso.operations.{$setting}", $value);

        $problems = [];

        foreach (app(OperationsCheck::class)->checks() as $check) {
            try {
                $check();
            } catch (\InvalidArgumentException $exception) {
                $problems[] = $exception->getMessage();
            }
        }

        self::assertSame([$message], $problems);
    }

    /**
     * A malformed cadence is reported and its task skipped; the rest still run.
     *
     * @return void
     */
    public function testAMalformedCadenceSkipsOnlyItsTask(): void
    {
        Exceptions::fake();

        config()->set('sso.operations.cadence.prune', 'hourly');

        self::assertSame(['sso:domains:recheck', 'sso:metadata:refresh', 'sso:keys:expiring'], array_keys($this->registered()));

        $message = 'sso.operations.cadence.prune must be a cron expression, or null or empty for none.';

        Exceptions::assertReported(static fn (\InvalidArgumentException $exception): bool => $exception->getMessage() === $message);
        Exceptions::assertReportedCount(1);
    }

    /**
     * Rows of `[setting, value]`: malformed mutex settings.
     *
     * @return iterable<string, array{0: string, 1: mixed}>
     */
    public static function provideMalformedMutexSettings(): iterable
    {
        yield 'the switch' => ['cache_mutexes', 'perhaps'];
        yield 'the minutes' => ['mutex_minutes', 0];
    }

    /**
     * A malformed mutex setting is reported and every task runs without one.
     *
     * @param  string  $setting
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMalformedMutexSettings')]
    public function testAMalformedMutexSettingRunsEveryTaskWithoutOne(string $setting, mixed $value): void
    {
        Exceptions::fake();

        config()->set('sso.operations.cache_mutexes', true);
        config()->set("sso.operations.{$setting}", $value);

        $events = $this->registered();

        self::assertCount(4, $events);

        foreach ($events as $event) {
            self::assertFalse($event->withoutOverlapping);
            self::assertFalse($event->onOneServer);
        }

        Exceptions::assertReported(\InvalidArgumentException::class);
        Exceptions::assertReportedCount(1);
    }

    /**
     * Mutex minutes are not read while the mutexes are off.
     *
     * @return void
     */
    public function testMutexMinutesAreIgnoredWhileTheMutexesAreOff(): void
    {
        Exceptions::fake();

        config()->set('sso.operations.mutex_minutes', 0);

        self::assertCount(4, $this->registered());

        Exceptions::assertNothingReported();
    }

    /**
     * The defaults apply when nothing is set, and an unknown task is refused.
     *
     * @return void
     */
    public function testTheDefaultsApplyWhenNothingIsSet(): void
    {
        config()->set('sso.operations', []);

        $settings = app(OperationsSettings::class);

        foreach (OperationsSettings::TASKS as $task => $cadence) {
            self::assertSame($cadence, $settings->cadence($task));
        }

        self::assertFalse($settings->usesCacheMutexes());
        self::assertSame(60, $settings->mutexMinutes());
        self::assertSame(array_keys(OperationsSettings::TASKS), array_keys(OperationsSchedule::COMMANDS));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('`anything` is not an operations task.');

        $settings->cadence('anything');
    }

    /**
     * The check applies while the package is in use.
     *
     * @return void
     */
    public function testTheCheckAppliesWhileThePackageIsInUse(): void
    {
        self::assertTrue(app(OperationsCheck::class)->applies());
        self::assertCount(6, app(OperationsCheck::class)->checks());

        config()->set('sso.features.oidc', false);

        self::assertFalse(app(OperationsCheck::class)->applies());
    }

    /**
     * The events a fresh schedule holds once registered, by command.
     *
     * @return array<string, \Illuminate\Console\Scheduling\Event>
     */
    private function registered(): array
    {
        $schedule = new Schedule;

        app(OperationsSchedule::class)->register($schedule);

        $events = [];

        foreach ($schedule->events() as $event) {

            self::assertNotInstanceOf(CallbackEvent::class, $event);

            foreach (array_filter(OperationsSchedule::COMMANDS, static fn (string $command): bool => str_contains((string) $event->command, $command)) as $command) {
                $events[$command] = $event;
            }
        }

        return $events;
    }
}
