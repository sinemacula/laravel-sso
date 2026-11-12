<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Installation;

use Illuminate\Console\Application as Artisan;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Configuration\ApplicationBuilder;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Operations\OperationsSchedule;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The installation guide's schedule wiring.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OperationsSchedule::class)]
final class InstallationExampleTest extends ExampleTestCase
{
    /**
     * The schedule holds each operation once, on its default cadence.
     *
     * @return void
     */
    public function testTheScheduleRunsEachOperationOnceOnItsDefaultCadence(): void
    {
        self::assertSame([
            ['sso:prune', '0 * * * *'],
            ['sso:domains:recheck', '0 * * * *'],
            ['sso:metadata:refresh', '*/5 * * * *'],
            ['sso:keys:expiring', '0 0 * * *'],
        ], $this->operationsOnStarting());
    }

    /**
     * With every protocol off, as installed, the schedule holds no operation.
     *
     * @return void
     */
    public function testTheScheduleHoldsNothingUntilAProtocolIsOn(): void
    {
        config()->set('sso.features.saml2', false);
        config()->set('sso.features.oidc', false);

        self::assertSame([], $this->operationsOnStarting());
    }

    /**
     * Each operation's command and cadence, in order, once the guide's
     * bootstrap starts Artisan.
     *
     * @return list<array{0: string, 1: string}>
     */
    private function operationsOnStarting(): array
    {
        /** @var \Closure(\Illuminate\Foundation\Configuration\ApplicationBuilder): \Illuminate\Foundation\Application $bootstrap */
        $bootstrap = require __DIR__ . '/bootstrap/app.php';

        $application = app();

        $bootstrap(new ApplicationBuilder($application));

        // Starting a console application runs what the builder wired to it
        new Artisan($application, $application->make(Dispatcher::class), $application->version());

        $operations = [];

        foreach ($application->make(Schedule::class)->events() as $event) {

            $command = Str::afterLast((string) $event->command, ' ');

            if (!in_array($command, OperationsSchedule::COMMANDS, true)) {
                continue;
            }

            $operations[] = [$command, $event->expression];
        }

        return $operations;
    }
}
