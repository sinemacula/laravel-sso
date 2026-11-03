<?php

declare(strict_types = 1);

namespace Tests\Feature\Operations;

use Illuminate\Console\Scheduling\CallbackEvent;
use Illuminate\Console\Scheduling\Event as ScheduledEvent;
use Illuminate\Console\Scheduling\Schedule;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Operations\OperationsCheck;
use SineMacula\Laravel\Sso\Operations\OperationsSchedule;
use SineMacula\Laravel\Sso\Operations\OperationsSettings;
use Tests\Concerns\UsesUnreliableCache;
use Tests\TestCase;

/**
 * Feature tests for the operations schedule (SSO-11.11, SSO-11.12): the four
 * commands on their default cadences, each cadence configurable or left to the
 * application, nothing while the package is not in use, no cache asked by
 * default, and mutexes only on opting in, with their expiry. Also the settings'
 * validation and the boot check. `CacheOutageTest` runs them through
 * `schedule:run` with the cache down, lying and stuck.
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
     * The four commands are registered on their default cadences, each on every
     * server, with no mutex.
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
     * Each cadence is the setting's, and a task with none is left to the
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
     * While the package is not in use nothing is registered, since the tables
     * the commands read may not exist.
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
     * Opting in with no expiry set takes an hour, far short of Laravel's own
     * day, so that a dead process stops a task for no longer.
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
     * By default nothing the helper registers touches the cache: with the cache
     * down, asking each task whether it overlaps does not call it.
     * `schedule:run` itself, which the framework's polling sends to the cache,
     * has its tests in `CacheOutageTest`.
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
     * A malformed setting fails closed, naming it, in the schedule and in the
     * boot check alike.
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

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        app(OperationsSchedule::class)->register(app(Schedule::class));

        app(OperationsSettings::class)->mutexMinutes();
    }

    /**
     * The defaults apply when nothing is set; a task the package does not have
     * is a caller's mistake.
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
     * The events a fresh schedule holds once the helper has registered them, by
     * the command each runs.
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
