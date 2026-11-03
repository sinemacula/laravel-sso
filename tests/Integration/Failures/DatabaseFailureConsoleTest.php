<?php

declare(strict_types = 1);

namespace Tests\Integration\Failures;

use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Console\CheckConfigurationCommand;
use SineMacula\Laravel\Sso\Console\ExpiringKeysCommand;
use SineMacula\Laravel\Sso\Console\PruneCommand;
use SineMacula\Laravel\Sso\Console\RecheckDomainsCommand;
use SineMacula\Laravel\Sso\Console\RefreshMetadataCommand;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Pruning\Enums\PruneKind;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use Tests\Concerns\FailsDatabaseStatements;
use Tests\Concerns\FlowRoutes;
use Tests\Concerns\MakesPrunableRows;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * A failing statement in a console command (SSO-11.4): each of `sso:prune`,
 * `sso:domains:recheck`, `sso:metadata:refresh` and `sso:keys:expiring` exits
 * non-zero, at its first read and past it, naming the exception by its class
 * and printing no statement, binding or message. `sso:check` opens no database
 * connection, so a failing database changes nothing it says.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PruneCommand::class)]
#[CoversClass(RecheckDomainsCommand::class)]
#[CoversClass(RefreshMetadataCommand::class)]
#[CoversClass(ExpiringKeysCommand::class)]
#[CoversClass(CheckConfigurationCommand::class)]
final class DatabaseFailureConsoleTest extends TestCase
{
    use FailsDatabaseStatements, FlowRoutes, MakesPrunableRows;

    /** @var string The tenant of the connections here. */
    private const string TENANT = 'tenant-console-failures';

    /** @var string The class every command names. */
    private const string EXCEPTION = 'Illuminate\Database\QueryException';

    /** @var string The token `makeDomain()` gives a claim. */
    private const string TOKEN = 'abababababababababababababababababababababababababababababababab';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeDnsResolver The resolver a recheck looks records up through. */
    private FakeDnsResolver $dns;

    /**
     * Create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->prepareFlows();
        $this->createEveryTable();

        $this->dns = new FakeDnsResolver;

        $resolver = $this->dns;

        $this->app?->bind(DnsResolver::class, static fn (): DnsResolver => $resolver);

        config()->set('sso.features.metadata_refresh', true);
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropEveryTable();

        parent::tearDown();
    }

    /**
     * Rows of `[kind, table]`: each kind a prune deletes, and where.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind, 1: string}>
     */
    public static function provideKinds(): iterable
    {
        yield 'requests' => [PruneKind::AUTHORIZATION_REQUESTS, 'sso_authorization_requests'];
        yield 'codes' => [PruneKind::HANDOFF_CODES, 'sso_handoff_codes'];
        yield 'single-use keys' => [PruneKind::SINGLE_USE_KEYS, 'sso_single_use_keys'];
        yield 'reservations' => [PruneKind::RESERVATIONS, 'sso_links'];
        yield 'pending claims' => [PruneKind::PENDING_CLAIMS, 'sso_domains'];
        yield 'counters' => [PruneKind::RATE_LIMITS, 'sso_rate_limits'];
    }

    /**
     * A prune failing to select a kind exits non-zero, names the kind and the
     * class, and says what it committed of the others.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @param  string  $table
     * @return void
     */
    #[DataProvider('provideKinds')]
    public function testAPruneFailingToSelectExitsNonZero(PruneKind $kind, string $table): void
    {
        $this->failStatement(self::onTable('select', $table));

        [$code, $output] = $this->ranCommand('sso:prune');

        self::assertSame(1, $code);
        self::assertStringContainsString("The prune of {$kind->value} stopped on " . self::EXCEPTION . '.', $output);
        $this->assertNothingOfTheStatement($output);
    }

    /**
     * A prune failing to delete a row it selected, past its first read, keeps
     * what the other kinds deleted, exits non-zero and prints nothing of the
     * row; run again, it finishes.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @param  string  $table
     * @return void
     */
    #[DataProvider('provideKinds')]
    public function testAPruneFailingToDeleteExitsNonZeroAndFinishesWhenRunAgain(PruneKind $kind, string $table): void
    {
        $connection = $this->makeConnection(['tenant_id' => self::TENANT]);
        $at         = $this->flowClock->now()->subDays(2);
        $keys       = [];

        foreach (PruneKind::cases() as $case) {
            $keys[] = $this->prunableRow($case, $connection, $at);
        }

        $this->failStatement(self::onTable('delete', $table));

        [$code, $output] = $this->ranCommand('sso:prune');

        self::assertSame(1, $code);
        self::assertStringContainsString("{$kind->value} 0", $output);
        self::assertStringContainsString("The prune of {$kind->value} stopped on " . self::EXCEPTION . '.', $output);
        $this->assertNothingOfTheStatement($output, array_values(array_filter($keys, static fn (string $key): bool => strlen($key) > 8)));

        [$again, $finished] = $this->ranCommand('sso:prune');

        self::assertSame(0, $again);
        self::assertStringContainsString("{$kind->value} 1", $finished);
    }

    /**
     * Rows of `[verb, table]`: what a recheck reads and writes for a claim.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideRecheckStatements(): iterable
    {
        yield 'selecting the claims' => ['select', 'sso_domains'];
        yield 'locking the connection' => ['select', 'sso_connections'];
        yield 'leasing the claim' => ['update', 'sso_domains'];
    }

    /**
     * A recheck that fails exits non-zero, and prints no domain or token.
     *
     * @param  string  $verb
     * @param  string  $table
     * @return void
     */
    #[DataProvider('provideRecheckStatements')]
    public function testARecheckExitsNonZero(string $verb, string $table): void
    {
        $domain = 'console.example.com';

        $this->flowVerifiedDomain($this->makeConnection(['tenant_id' => self::TENANT]), $domain);
        $this->flowClock->advance(3600);
        $this->dns->found("_sso-verification.{$domain}", self::TOKEN);

        $this->failStatement(self::onTable($verb, $table));

        [$code, $output] = $this->ranCommand('sso:domains:recheck');

        self::assertSame(1, $code);
        self::assertStringContainsString('The domain recheck stopped on ' . self::EXCEPTION . '.', $output);
        $this->assertNothingOfTheStatement($output, [$domain, self::TOKEN]);
    }

    /**
     * Rows of `[options, verb, table]`: a queueing run's read, and a run in the
     * command's own read and claim.
     *
     * @return iterable<string, array{0: array<string, bool>, 1: string, 2: string}>
     */
    public static function provideRefreshStatements(): iterable
    {
        yield 'listing to queue' => [[], 'select', 'sso_connections'];
        yield 'listing to refresh' => [['--sync' => true], 'select', 'sso_connections'];
        yield 'claiming the connection' => [['--sync' => true], 'update', 'sso_connections'];
    }

    /**
     * A refresh that fails exits non-zero, and prints nothing of the
     * connection.
     *
     * @param  array<string, bool>  $options
     * @param  string  $verb
     * @param  string  $table
     * @return void
     */
    #[DataProvider('provideRefreshStatements')]
    public function testARefreshExitsNonZero(array $options, string $verb, string $table): void
    {
        $issuer     = 'https://op-console.example.test';
        $connection = $this->makeConnection(['tenant_id' => self::TENANT, 'enabled' => true, 'settings' => ['issuer' => $issuer, 'metadata_refresh' => true]]);

        $this->failStatement(self::onTable($verb, $table));

        [$code, $output] = $this->ranCommand('sso:metadata:refresh', $options);

        self::assertSame(1, $code);
        self::assertStringContainsString('The metadata refresh stopped on ' . self::EXCEPTION . '.', $output);
        $this->assertNothingOfTheStatement($output, [$issuer, $connection->id]);
    }

    /**
     * Rows of `[verb, table]`: what a report reads and writes for a key.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideExpiryStatements(): iterable
    {
        yield 'paging the keys' => ['select', 'sso_keys'];
        yield 'reading the connections' => ['select', 'sso_connections'];
        yield 'claiming the warning' => ['update', 'sso_keys'];
    }

    /**
     * A report that fails exits non-zero, and prints nothing of the key's
     * material.
     *
     * @param  string  $verb
     * @param  string  $table
     * @return void
     */
    #[DataProvider('provideExpiryStatements')]
    public function testAnExpiryReportExitsNonZero(string $verb, string $table): void
    {
        $key = $this->expiringKey($this->makeConnection(['tenant_id' => self::TENANT]));

        $this->failStatement(self::onTable($verb, $table));

        [$code, $output] = $this->ranCommand('sso:keys:expiring');

        self::assertSame(1, $code);
        self::assertStringContainsString('The expiry report stopped on ' . self::EXCEPTION . '.', $output);
        $this->assertNothingOfTheStatement($output, [$key->fingerprint]);
    }

    /**
     * `sso:check` opens no database connection: with every statement armed to
     * fail it runs no statement, and says and exits as it does without.
     *
     * @return void
     */
    public function testACheckIsNotConcerned(): void
    {
        $this->failStatement('/.*/');

        [$code, $output] = $this->ranCommand('sso:check');

        self::assertSame(0, $this->databaseFailuresFired());

        $this->disarmDatabaseFailures();

        self::assertSame([$code, $output], $this->ranCommand('sso:check'));
        self::assertStringNotContainsString(self::INJECTED_FAILURE, $output);
    }

    /**
     * Assert the output shows nothing of a statement, a message or the values
     * given.
     *
     * @param  string  $output
     * @param  list<string>  $values
     * @return void
     */
    private function assertNothingOfTheStatement(string $output, array $values = []): void
    {
        foreach ([self::INJECTED_FAILURE, 'sso_', 'select ', 'insert ', 'update ', 'delete ', ...$values] as $leak) {
            self::assertStringNotContainsString($leak, $output);
        }
    }

    /**
     * Run the command, answering its exit code and what it printed.
     *
     * @param  string  $command
     * @param  array<string, bool>  $options
     * @return array{0: int, 1: string}
     */
    private function ranCommand(string $command, array $options = []): array
    {
        return [Artisan::call($command, $options), Artisan::output()];
    }

    /**
     * A key of the connection that ends tomorrow.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Models\ConnectionKey
     */
    private function expiringKey(Connection $connection): ConnectionKey
    {
        $pem    = Certificates::distinct(60);
        $masked = MaskedKey::fromCertificate($pem);
        $key    = new ConnectionKey;

        $key->forceFill([
            'connection_id' => $connection->id,
            'use'           => KeyUse::IDP_SIGNING,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'certificate'   => $pem,
            'public_key'    => (string) $masked->publicKey,
            'fingerprint'   => (string) $masked->fingerprint,
            'not_after'     => $this->flowClock->now()->addDay(),
        ])->save();

        return $key;
    }
}
