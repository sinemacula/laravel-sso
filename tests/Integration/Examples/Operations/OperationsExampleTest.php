<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Operations;

use Illuminate\Console\Application as ConsoleApplication;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Configuration\ApplicationBuilder;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Console\ExpiringKeysCommand;
use SineMacula\Laravel\Sso\Events\KeyNearingExpiry;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\ExpiryReport;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Operations\OperationsSchedule;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/operations.md` (SSO-2.6, SSO-11.11, SSO-11.12,
 * SSO-12.5), on the shared example harness: once Artisan starts, the schedule
 * its `bootstrap/app.php` wires holds the four operations on their cadences,
 * none with a cache mutex unless the application opts in, none whose cadence is
 * left to the application, and none while no protocol is on; and the listener
 * on `KeyNearingExpiry` tells the security team of a certificate nearing its
 * end, with the connection, the fingerprint, the end of validity and the
 * threshold reached, once for each more urgent threshold, while a certificate
 * not yet within the largest threshold is not warned of. A dispatch that throws
 * fails the run and leaves the warning to the next.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OperationsSchedule::class)]
#[CoversClass(ExpiryReport::class)]
#[CoversClass(ExpiringKeysCommand::class)]
#[CoversClass(KeyNearingExpiry::class)]
final class OperationsExampleTest extends ExampleTestCase
{
    /**
     * Once Artisan starts, the schedule the guide wires holds each operation
     * once, on its default cadence, and none takes a cache mutex.
     *
     * @return void
     */
    public function testTheScheduleRunsEachOperationOnItsCadence(): void
    {
        self::assertSame([
            ['sso:prune', '0 * * * *', false, null],
            ['sso:domains:recheck', '0 * * * *', false, null],
            ['sso:metadata:refresh', '*/5 * * * *', false, null],
            ['sso:keys:expiring', '0 0 * * *', false, null],
        ], $this->operationsOnStarting());
    }

    /**
     * A cadence set is the one scheduled, and a task whose cadence is `null` or
     * empty is left to the application's own schedule.
     *
     * @return void
     */
    public function testACadenceLeftToTheApplicationIsNotScheduled(): void
    {
        config()->set('sso.operations.cadence.prune', '30 * * * *');
        config()->set('sso.operations.cadence.metadata_refresh', '');
        config()->set('sso.operations.cadence.expiry_report', null);

        self::assertSame([
            ['sso:prune', '30 * * * *', false, null],
            ['sso:domains:recheck', '0 * * * *', false, null],
        ], $this->operationsOnStarting());
    }

    /**
     * Opting in to the cache mutexes runs each operation on one server and
     * without overlapping, its mutex expiring after the minutes set.
     *
     * @return void
     */
    public function testTheCacheMutexesAreOptedInToForEveryOperation(): void
    {
        config()->set('sso.operations.cache_mutexes', true);
        config()->set('sso.operations.mutex_minutes', 30);

        self::assertSame([
            ['sso:prune', '0 * * * *', true, 30],
            ['sso:domains:recheck', '0 * * * *', true, 30],
            ['sso:metadata:refresh', '*/5 * * * *', true, 30],
            ['sso:keys:expiring', '0 0 * * *', true, 30],
        ], $this->operationsOnStarting());
    }

    /**
     * While no protocol is on, the schedule holds none of the operations, since
     * the tables they read may not exist yet.
     *
     * @return void
     */
    public function testNothingIsScheduledWhileNoProtocolIsOn(): void
    {
        config()->set('sso.features.saml2', false);
        config()->set('sso.features.oidc', false);

        self::assertSame([], $this->operationsOnStarting());
    }

    /**
     * Six days before the provider's certificate ends, the report tells the
     * security team once, for the 7-day threshold, with the connection, the
     * fingerprint and the end of validity; a second run sends nothing more;
     * once the validity has ended, the 0-day warning follows. Thirty-one days
     * before, nothing is listed or sent.
     *
     * @return void
     */
    public function testTheSecurityTeamIsToldOnceForEachMoreUrgentThreshold(): void
    {
        $connectionId = $this->makeSamlConnection(new FakeSamlIdentityProvider);
        $certificate  = $this->certificateOf($connectionId);
        $notAfter     = $certificate->notAfter ?? self::fail('The certificate has no end of validity.');

        Notification::fake();

        require __DIR__ . '/listeners/key-nearing-expiry.php';

        $this->clock->setTo($notAfter->subDays(31));

        self::assertSame(0, Artisan::call('sso:keys:expiring'));
        self::assertStringContainsString('Keys listed: 0, expired 0; warnings: notified 0', Artisan::output());
        Notification::assertNothingSent();

        $this->clock->setTo($notAfter->subDays(6));

        self::assertSame(0, Artisan::call('sso:keys:expiring'));

        $ends = $notAfter->utc()->format('Y-m-d\TH:i:s\Z');

        self::assertStringContainsString("[expiring] key {$certificate->id} (connection {$connectionId}, idp_signing) ends {$ends}, threshold 7: notified", Artisan::output());
        self::assertSame(0, Artisan::call('sso:keys:expiring'));
        self::assertStringContainsString('threshold 7: already_notified', Artisan::output());

        $this->clock->setTo($notAfter);

        self::assertSame(0, Artisan::call('sso:keys:expiring'));
        self::assertStringContainsString("[expired] key {$certificate->id} (connection {$connectionId}, idp_signing) ends {$ends}, threshold 0: notified", Artisan::output());

        $fingerprint = (string) $certificate->key->fingerprint;

        self::assertSame([
            [SecurityTeam::ADDRESS, $connectionId, $fingerprint, $ends, 7],
            [SecurityTeam::ADDRESS, $connectionId, $fingerprint, $ends, 0],
        ], self::told());
    }

    /**
     * When telling the team throws, as a mailer that cannot send does, the key
     * ends `failed` and the run exits `1`; the warning is not recorded as sent,
     * so the next run sends it.
     *
     * @return void
     */
    public function testAWarningThatCouldNotBeSentIsSentByTheNextRun(): void
    {
        $connectionId = $this->makeSamlConnection(new FakeSamlIdentityProvider);
        $certificate  = $this->certificateOf($connectionId);
        $notAfter     = $certificate->notAfter ?? self::fail('The certificate has no end of validity.');

        config()->set('mail.mailers.unavailable', ['transport' => 'failover', 'mailers' => []]);
        config()->set('mail.default', 'unavailable');

        require __DIR__ . '/listeners/key-nearing-expiry.php';

        $this->clock->setTo($notAfter->subDays(6));

        self::assertSame(1, Artisan::call('sso:keys:expiring'));

        $output = Artisan::output();

        self::assertStringContainsString("[expiring] key {$certificate->id} (connection {$connectionId}, idp_signing)", $output);
        self::assertStringContainsString('threshold 7: failed', $output);
        self::assertStringContainsString('notified 0, already_notified 0, not_due 0, claimed 0, failed 1', $output);

        Notification::fake();

        self::assertSame(0, Artisan::call('sso:keys:expiring'));
        self::assertStringContainsString('threshold 7: notified', Artisan::output());
        self::assertSame([[SecurityTeam::ADDRESS, $connectionId, (string) $certificate->key->fingerprint, $notAfter->utc()->format('Y-m-d\TH:i:s\Z'), 7]], self::told());
    }

    /**
     * What the security team was told, in order: the address, the connection,
     * the fingerprint, the end of validity and the threshold of each.
     *
     * @return list<array{0: mixed, 1: ?string, 2: string, 3: string, 4: int}>
     */
    private static function told(): array
    {
        $told = [];

        foreach (Notification::sentNotifications()[AnonymousNotifiable::class] ?? [] as $notifications) {

            foreach ($notifications[CertificateExpiring::class] ?? [] as $sent) {

                $notification = $sent['notification'];
                $notifiable   = $sent['notifiable'];

                self::assertInstanceOf(CertificateExpiring::class, $notification);
                self::assertInstanceOf(AnonymousNotifiable::class, $notifiable);
                self::assertSame(['mail'], $sent['channels']);

                $told[] = [
                    $notifiable->routeNotificationFor('mail'),
                    $notification->connectionId,
                    $notification->fingerprint,
                    $notification->notAfter->utc()->format('Y-m-d\TH:i:s\Z'),
                    $notification->thresholdDays,
                ];
            }
        }

        return $told;
    }

    /**
     * The certificate the connection trusts, as the key service lists it.
     *
     * @param  string  $connectionId
     * @return \SineMacula\Laravel\Sso\Keys\KeySummary
     */
    private function certificateOf(string $connectionId): KeySummary
    {
        $certificates = array_values(array_filter(
            app(KeyService::class)->keys(self::TENANT, $connectionId) ?? [],
            static fn (KeySummary $summary): bool => $summary->use === KeyUse::IDP_SIGNING,
        ));

        self::assertCount(1, $certificates);

        return $certificates[0];
    }

    /**
     * Configure the application under test with the guide's
     * `bootstrap/app.php`, start Artisan as `php artisan` does, and answer each
     * operation the schedule then holds, in order, as its command, its cadence,
     * whether it runs on one server, and the minutes its mutex expires after,
     * or `null` when it may overlap.
     *
     * @return list<array{0: string, 1: string, 2: bool, 3: ?int}>
     */
    private function operationsOnStarting(): array
    {
        /** @var \Closure(\Illuminate\Foundation\Configuration\ApplicationBuilder): \Illuminate\Foundation\Application $bootstrap */
        $bootstrap = require __DIR__ . '/bootstrap/app.php';

        $application = app();

        $bootstrap(new ApplicationBuilder($application));

        // Starting a console application runs what the builder wired to it
        new ConsoleApplication($application, $application->make(Dispatcher::class), $application->version());

        $operations = [];

        foreach ($application->make(Schedule::class)->events() as $event) {

            $command = Str::afterLast((string) $event->command, ' ');

            if (!in_array($command, OperationsSchedule::COMMANDS, true)) {
                continue;
            }

            $operations[] = [$command, $event->expression, $event->onOneServer, $event->withoutOverlapping ? $event->expiresAt : null];
        }

        return $operations;
    }
}
