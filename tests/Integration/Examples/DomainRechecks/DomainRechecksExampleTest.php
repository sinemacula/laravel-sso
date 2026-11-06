<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\DomainRechecks;

use Illuminate\Console\Application as ConsoleApplication;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Configuration\ApplicationBuilder;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Console\RecheckDomainsCommand;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Domains\DomainRechecker;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Domains\DomainSummary;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Domains\Enums\DomainStatus;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Domains\RecheckReport;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/domain-rechecks.md` (SSO-3.3, SSO-11.12,
 * SSO-12.5), on the shared example harness: the schedule its
 * `bootstrap/app.php` wires runs the recheck hourly; a recheck run from code
 * reports a record still published as confirmed, one gone as suspended, with
 * its lapse three days on, and a lookup that failed, and a resolver that throws
 * as such; and the command, with a fake resolver bound, suspends a domain whose
 * record has gone and exits `0`, while a failed lookup changes nothing and
 * fails it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainRechecker::class)]
#[CoversClass(RecheckReport::class)]
#[CoversClass(RecheckDomainsCommand::class)]
final class DomainRechecksExampleTest extends ExampleTestCase
{
    /** @var string The connection every domain is claimed for. */
    private string $connectionId;

    /**
     * Make the connection the domains are claimed for.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->connectionId = $this->makeOidcConnection(new FakeOpenIdProvider(clock: $this->clock));
    }

    /**
     * Once Artisan starts, the schedule the guide's `bootstrap/app.php` wires
     * holds the recheck once, hourly, on the hour.
     *
     * @return void
     */
    public function testTheScheduleRunsTheRecheckHourly(): void
    {
        /** @var \Closure(\Illuminate\Foundation\Configuration\ApplicationBuilder): \Illuminate\Foundation\Application $bootstrap */
        $bootstrap = require __DIR__ . '/bootstrap/app.php';

        $application = app();

        $bootstrap(new ApplicationBuilder($application));

        // Starting a console application runs what the builder wired to it
        new ConsoleApplication($application, $application->make(Dispatcher::class), $application->version());

        $expressions = [];

        foreach ($application->make(Schedule::class)->events() as $event) {

            if (Str::afterLast((string) $event->command, ' ') !== 'sso:domains:recheck') {
                continue;
            }

            $expressions[] = $event->expression;
        }

        self::assertSame(['0 * * * *'], $expressions);
    }

    /**
     * A recheck run from code an hour after three domains were verified
     * confirms the one whose record is still published, suspends the one whose
     * record has gone, fixing its lapse three days on, and reports the one
     * whose lookup failed, which it leaves as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecheckFromCodeReportsEachOutcome(): void
    {
        $published = $this->verified('example.com');
        $gone      = $this->verified('example.org');
        $failing   = $this->verified('example.net');

        // An hour on, as the schedule runs it
        $this->clock->advance(3600);
        $this->dns->absent($gone->recordName);
        $this->dns->failing($failing->recordName);

        // @snippet-start recheck-from-code
        $report = app(DomainRechecker::class)->recheckAll(new ClientContext(null, null)); // no client, as the schedule runs it

        self::assertTrue($report->hasLookupFailures());
        self::assertFalse($report->hasResolverThrows());
        self::assertSame(1, $report->count(RecheckOutcome::SUSPENDED));

        // Entries and counts, snake_case, times in UTC
        $json = json_decode((string) json_encode($report), true);

        self::assertSame(1, $json['counts']['lookup_failed']);
        self::assertContains('2026-11-04T10:30:00Z', array_column($json['entries'], 'lapses_at'));
        // @snippet-end recheck-from-code
        self::assertCount(3, $report->entries);
        self::assertSame(1, $report->count(RecheckOutcome::CONFIRMED));
        self::assertSame(1, $report->count(RecheckOutcome::LOOKUP_FAILED));
        $this->dns->assertLookedUp($published->recordName, 2);

        $suspended = $this->summaryOf('example.org');

        self::assertSame('2026-11-01T10:30:00Z', $suspended->linkingSuspendedAt?->toIso8601ZuluString());
        self::assertSame('2026-11-04T10:30:00Z', $suspended->lapsesAt?->toIso8601ZuluString());

        $unanswered = $this->summaryOf('example.net');

        self::assertSame('2026-11-01T09:30:00Z', $unanswered->lastSuccessfulCheckAt?->toIso8601ZuluString());
        self::assertNull($unanswered->linkingSuspendedAt);
        self::assertSame('2026-11-01T10:30:00Z', $this->summaryOf('example.com')->lastSuccessfulCheckAt?->toIso8601ZuluString());
    }

    /**
     * A resolver that throws is reported as such, never as a failed lookup, and
     * the domain is left exactly as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResolverThatThrowsIsReportedAndChangesNothing(): void
    {
        $claimed = $this->verified('example.com');

        $this->clock->advance(3600);
        $this->dns->answer($claimed->recordName, static function (string $name): never {
            throw new \RuntimeException("The resolver could not reach {$name}.");
        });

        $report = app(DomainRechecker::class)->recheckAll(new ClientContext(null, null)); // no client, as the schedule runs it

        self::assertTrue($report->hasResolverThrows());
        self::assertFalse($report->hasLookupFailures());
        self::assertSame(1, $report->count(RecheckOutcome::RESOLVER_THREW));

        $summary = $this->summaryOf('example.com');

        self::assertSame(DomainState::VERIFIED, $summary->state);
        self::assertSame('2026-11-01T09:30:00Z', $summary->lastSuccessfulCheckAt?->toIso8601ZuluString());
        self::assertNull($summary->linkingSuspendedAt);
    }

    /**
     * With a fake resolver bound that answers the domain's record as gone, the
     * command suspends the domain, which still routes until it lapses three
     * days on, and exits `0`.
     *
     * @return void
     */
    public function testTheCommandSuspendsADomainWhoseRecordHasGone(): void
    {
        $this->verified('example.com');

        $this->clock->advance(3600);

        // @snippet-start recheck-testing
        app()->instance(DnsResolver::class, $dns = new FakeDnsResolver);

        $dns->absent('_sso-verification.example.com');

        self::assertSame(0, Artisan::call('sso:domains:recheck'));
        // @snippet-end recheck-testing
        $dns->assertLookedUp('_sso-verification.example.com', 1);

        $summary = $this->summaryOf('example.com');

        self::assertSame(DomainState::VERIFIED, $summary->state);
        self::assertSame('2026-11-01T10:30:00Z', $summary->linkingSuspendedAt?->toIso8601ZuluString());
        self::assertSame('2026-11-04T10:30:00Z', $summary->lapsesAt?->toIso8601ZuluString());
    }

    /**
     * A lookup that failed fails the command, which names the domain and counts
     * it, and changes nothing about the domain.
     *
     * @return void
     */
    public function testAFailedLookupFailsTheCommandAndChangesNothing(): void
    {
        $this->verified('example.com');

        $this->clock->advance(3600);
        $this->dns->failing('_sso-verification.example.com');

        self::assertSame(1, Artisan::call('sso:domains:recheck'));

        $output = Artisan::output();

        self::assertStringContainsString("[lookup_failed] example.com (connection {$this->connectionId})", $output);
        self::assertStringContainsString('lookup_failed 1, resolver_threw 0', $output);

        $summary = $this->summaryOf('example.com');

        self::assertSame(DomainState::VERIFIED, $summary->state);
        self::assertSame('2026-11-01T09:30:00Z', $summary->lastSuccessfulCheckAt?->toIso8601ZuluString());
        self::assertNull($summary->linkingSuspendedAt);
        self::assertNull($summary->lapsesAt);
    }

    /**
     * Claim the domain for the connection and verify it, the tenant having
     * published its record.
     *
     * @param  string  $domain
     * @return \SineMacula\Laravel\Sso\Domains\DomainSummary
     */
    private function verified(string $domain): DomainSummary
    {
        $domains = app(DomainService::class);
        $claimed = $domains->claim(self::TENANT, $this->connectionId, $domain, Clients::browser())->domain;

        self::assertNotNull($claimed);

        $this->dns->publishes($claimed);

        self::assertSame(DomainStatus::VERIFIED, $domains->verify(self::TENANT, $this->connectionId, $domain, Clients::browser())->status);

        return $claimed;
    }

    /**
     * The connection's claim of the domain, as the domain service reads it.
     *
     * @param  string  $domain
     * @return \SineMacula\Laravel\Sso\Domains\DomainSummary
     */
    private function summaryOf(string $domain): DomainSummary
    {
        return app(DomainService::class)->get(self::TENANT, $this->connectionId, $domain) ?? self::fail("The connection has no claim of {$domain}.");
    }
}
