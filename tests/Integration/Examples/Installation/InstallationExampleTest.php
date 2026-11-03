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
 * The installation guide's wiring (SSO-11.11, SSO-12.5), run on the shared
 * example harness: once Artisan starts, the schedule its `bootstrap/app.php`
 * wires holds the pruning, the domain recheck, the metadata refresh and the key
 * expiry report, each once on its default cadence; while no protocol is on, as
 * on a fresh install, it holds none of them, since the tables they read may not
 * exist yet.
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
     * Once Artisan starts, the schedule the guide wires holds each of the
     * package's operations exactly once, on its default cadence.
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
     * With every protocol off, as the package is installed, the schedule the
     * guide wires holds none of the package's operations.
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
     * Configure the application under test with the guide's
     * `bootstrap/app.php`, start Artisan as `php artisan` does, and answer each
     * of the package's operations the schedule then holds, in order, as its
     * command and its cadence.
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
