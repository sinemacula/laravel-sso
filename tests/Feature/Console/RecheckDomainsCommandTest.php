<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Console\RecheckDomainsCommand;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainRechecker;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Models\Domain;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\FailsDatabaseStatements;
use Tests\Feature\Domains\DomainServiceTestCase;

/**
 * Feature tests for `sso:domains:recheck`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecheckDomainsCommand::class)]
final class RecheckDomainsCommandTest extends DomainServiceTestCase
{
    use CapturesLogs, FailsDatabaseStatements;

    /** @var string The token `makeDomain()` gives a claim. */
    private const string TOKEN = 'abababababababababababababababababababababababababababababababab';

    /** @var string The summary of a run that checked nothing. */
    private const string NOTHING = 'Domains rechecked: confirmed 0, restored 0, suspended 0, still_failing 0, lapsed 0, lookup_failed 0, resolver_threw 0, skipped 0';

    /**
     * With no verified domain, the run prints the summary alone and passes.
     *
     * @return void
     */
    public function testWithNoDomainsPrintsTheSummaryAlone(): void
    {
        [$code, $output] = $this->recheckFromConsole();

        self::assertSame(0, $code);
        self::assertSame([self::NOTHING], $output);
    }

    /**
     * Each change is printed in check order, then the summary of outcomes.
     *
     * @return void
     */
    public function testPrintsEachChangeThenTheSummary(): void
    {
        $id = $this->connection->id;

        $this->verifiedClaim('lapsing.example.com', '2026-10-29T09:30:00Z', ['linking_suspended_at' => '2026-10-29T10:30:00Z', 'lapses_at' => '2026-11-01T10:00:00Z']);
        $this->verifiedClaim('restored.example.com', '2026-10-30T09:30:00Z', ['linking_suspended_at' => '2026-10-31T09:30:00Z', 'lapses_at' => '2026-11-03T09:30:00Z']);
        $this->verifiedClaim('absent.example.com', '2026-10-31T09:30:00Z');
        $this->verifiedClaim('confirmed.example.com', '2026-11-01T09:30:00Z');

        $this->clock->advance(3600);
        $this->dns
            ->found('_sso-verification.restored.example.com', self::TOKEN)
            ->absent('_sso-verification.absent.example.com')
            ->found('_sso-verification.confirmed.example.com', self::TOKEN);

        [$code, $output] = $this->recheckFromConsole();

        self::assertSame(0, $code);
        self::assertSame([
            "[lapsed] lapsing.example.com (connection {$id})",
            "[restored] restored.example.com (connection {$id})",
            "[suspended] absent.example.com (connection {$id})",
            'Domains rechecked: confirmed 1, restored 1, suspended 1, still_failing 0, lapsed 1, lookup_failed 0, resolver_threw 0, skipped 0',
        ], $output);
    }

    /**
     * A failed lookup is printed, counted, and fails the run.
     *
     * @return void
     */
    public function testAFailedLookupFailsTheRun(): void
    {
        $id = $this->connection->id;

        $this->verifiedClaim('example.com', '2026-11-01T09:30:00Z');
        $this->clock->advance(3600);
        $this->dns->failing('_sso-verification.example.com');

        [$code, $output] = $this->recheckFromConsole();

        self::assertSame(1, $code);
        self::assertSame([
            "[lookup_failed] example.com (connection {$id})",
            'Domains rechecked: confirmed 0, restored 0, suspended 0, still_failing 0, lapsed 0, lookup_failed 1, resolver_threw 0, skipped 0',
        ], $output);
    }

    /**
     * A second run with the same DNS reports nothing new.
     *
     * @return void
     */
    public function testASecondRunReportsNothingNew(): void
    {
        $id = $this->connection->id;

        $this->verifiedClaim('absent.example.com', '2026-10-31T09:30:00Z');
        $this->verifiedClaim('confirmed.example.com', '2026-11-01T09:30:00Z');

        $this->clock->advance(3600);
        $this->dns->absent('_sso-verification.absent.example.com')->found('_sso-verification.confirmed.example.com', self::TOKEN);

        [$first] = $this->recheckFromConsole();

        $state = Domain::query()->orderBy('id')->get()->map(static fn (Domain $claim): array => $claim->getAttributes())->all();

        [$second, $again] = $this->recheckFromConsole();

        self::assertSame([0, 0], [$first, $second]);
        self::assertSame([self::NOTHING], $again);
        self::assertSame($state, Domain::query()->orderBy('id')->get()->map(static fn (Domain $claim): array => $claim->getAttributes())->all());

        $this->clock->advance(3600);

        [, $later] = $this->recheckFromConsole();

        self::assertSame([
            "[still_failing] absent.example.com (connection {$id})",
            'Domains rechecked: confirmed 1, restored 0, suspended 0, still_failing 1, lapsed 0, lookup_failed 0, resolver_threw 0, skipped 0',
        ], $later);
    }

    /**
     * A throwing resolver is contained, logged by class, and the run goes on
     * and fails.
     *
     * @return void
     */
    public function testAResolverThatThrowsIsContainedAndTheRunGoesOn(): void
    {
        $id = $this->connection->id;

        $this->captureLogs();

        $thrower = $this->verifiedClaim('first.example.com', '2026-10-31T09:30:00Z');

        $this->verifiedClaim('second.example.com', '2026-11-01T08:30:00Z');
        $this->verifiedClaim('third.example.com', '2026-11-01T09:30:00Z');

        $this->clock->advance(3600);
        $this->dns
            ->answer('_sso-verification.first.example.com', static function (string $name): never {
                throw new \RuntimeException("SERVFAIL from ns1.provider.test for {$name}");
            })
            ->absent('_sso-verification.second.example.com')
            ->found('_sso-verification.third.example.com', self::TOKEN);

        $before = self::storedRow($thrower);

        [$code, $output] = $this->recheckFromConsole();

        self::assertSame(1, $code);
        self::assertSame([
            "[resolver_threw] first.example.com (connection {$id})",
            "[suspended] second.example.com (connection {$id})",
            'Domains rechecked: confirmed 1, restored 0, suspended 1, still_failing 0, lapsed 0, lookup_failed 0, resolver_threw 1, skipped 0',
        ], $output);
        self::assertSame($before, self::storedRow($thrower));
        self::assertNull($before['recheck_leased_until']);
        self::assertStringNotContainsString('SERVFAIL', implode("\n", $output));

        $this->dns->assertLookedUp('_sso-verification.first.example.com', 1);
        $this->dns->assertLookedUp('_sso-verification.second.example.com', 1);
        $this->dns->assertLookedUp('_sso-verification.third.example.com', 1);

        self::assertSame([
            ['channel' => 'sso_capture', 'level' => 'warning', 'message' => 'sso.domains.recheck_resolver_threw', 'context' => ['exception' => \RuntimeException::class]],
        ], $this->capturedLogRecords());
        $this->assertNothingLoggedContains('SERVFAIL', 'provider.test', 'first.example.com', $thrower->id);
    }

    /**
     * A resolver that throws fails the run even when no lookup failed.
     *
     * @return void
     */
    public function testAResolverThatThrowsAloneFailsTheRun(): void
    {
        $this->verifiedClaim('example.com', '2026-11-01T09:30:00Z');
        $this->clock->advance(3600);

        $this->dns->answer('_sso-verification.example.com', static function (): never {
            throw new \LogicException('The resolver is misconfigured.');
        });

        [$code, $output] = $this->recheckFromConsole();

        self::assertSame(1, $code);
        self::assertSame('Domains rechecked: confirmed 0, restored 0, suspended 0, still_failing 0, lapsed 0, lookup_failed 0, resolver_threw 1, skipped 0', $output[1]);
    }

    /**
     * A database error stops the run, naming its class alone.
     *
     * @return void
     */
    public function testADatabaseErrorStopsTheRunNamingItsClassAlone(): void
    {
        $claim = $this->verifiedClaim('example.com', '2026-11-01T09:30:00Z');

        $this->clock->advance(3600);
        $this->dns->found('_sso-verification.example.com', self::TOKEN);
        $this->failStatement(self::onTable('update', 'sso_domains'), 2);

        [$code, $output] = $this->recheckFromConsole();

        $leasedUntil = Domain::query()->findOrFail($claim->id)->recheck_leased_until;

        self::assertSame(1, $code);
        self::assertSame(1, $this->databaseFailuresFired());
        self::assertSame(['The domain recheck stopped on Illuminate\Database\QueryException.'], $output);
        self::assertStringNotContainsString(self::INJECTED_FAILURE, implode("\n", $output));
        self::assertSame(
            $this->clock->now()->addSeconds(DomainRechecker::LEASE_SECONDS)->toAtomString(),
            $leasedUntil?->toAtomString(),
        );
    }

    /**
     * A claim held by a dead run is taken over once its lease runs out.
     *
     * @return void
     */
    public function testARunThatDiedIsTakenOverOnceItsLeaseRunsOut(): void
    {
        $claim = $this->verifiedClaim('example.com', '2026-11-01T09:30:00Z');

        $this->clock->advance(3600);

        $this->dns->found('_sso-verification.example.com', self::TOKEN);
        $this->failStatement(self::onTable('update', 'sso_domains'), 2);

        [$died] = $this->recheckFromConsole();

        self::assertSame(1, $died);

        $checked = Domain::query()->findOrFail($claim->id)->last_successful_check_at;

        $this->clock->advance(DomainRechecker::LEASE_SECONDS - 1);

        [$held, $output] = $this->recheckFromConsole();

        self::assertSame(0, $held);
        self::assertSame(['Domains rechecked: confirmed 0, restored 0, suspended 0, still_failing 0, lapsed 0, lookup_failed 0, resolver_threw 0, skipped 1'], $output);
        self::assertSame($checked?->toAtomString(), Domain::query()->findOrFail($claim->id)->last_successful_check_at?->toAtomString());

        $this->clock->advance(1);

        [$taken, $output] = $this->recheckFromConsole();

        self::assertSame(0, $taken);
        self::assertSame(['Domains rechecked: confirmed 1, restored 0, suspended 0, still_failing 0, lapsed 0, lookup_failed 0, resolver_threw 0, skipped 0'], $output);
        self::assertNull(Domain::query()->findOrFail($claim->id)->recheck_leased_until);
    }

    /**
     * Make a verified claim of the domain, last checked at the time given.
     *
     * @param  string  $domain
     * @param  string  $checkedAt
     * @param  array<string, string>  $times
     * @return \SineMacula\Laravel\Sso\Models\Domain
     */
    private function verifiedClaim(string $domain, string $checkedAt, array $times = []): Domain
    {
        $attributes = array_map(static fn (string $time): CarbonImmutable => CarbonImmutable::parse($time), $times);

        return $this->makeDomain($this->connection, $domain, [
            'state'                    => DomainState::VERIFIED,
            'last_successful_check_at' => CarbonImmutable::parse($checkedAt),
        ] + $attributes);
    }

    /**
     * The claim's row as the database holds it, every column as stored.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @return array<string, mixed>
     */
    private static function storedRow(Domain $claim): array
    {
        return (array) DB::connection(StorageConnection::name())->table('sso_domains')->where('id', $claim->id)->first();
    }

    /**
     * Run `sso:domains:recheck` and answer its exit code and non-empty trimmed
     * lines.
     *
     * @return array{int, list<string>}
     */
    private function recheckFromConsole(): array
    {
        $code   = Artisan::call('sso:domains:recheck');
        $output = array_values(array_filter(explode("\n", Artisan::output()), static fn (string $line): bool => trim($line) !== ''));

        return [$code, array_map(trim(...), $output)];
    }
}
