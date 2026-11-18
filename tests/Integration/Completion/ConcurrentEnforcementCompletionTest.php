<?php

declare(strict_types = 1);

namespace Tests\Integration\Completion;

use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Completion\CompletionLocks;
use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Completion\Stages\CheckEnforcement;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Enforcement\EnforcementFinder;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RaceFlows;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Enforcement\TableSessions;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Links\ExampleLinks;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\TestCase;

/**
 * Integration tests racing a completion against turning enforcement on.
 *
 * Orders are forced with signal files and lock waits, never timing. Skipped on
 * SQLite and without `pcntl`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionPipeline::class)]
#[CoversClass(CompletionLocks::class)]
#[CoversClass(CheckEnforcement::class)]
final class ConcurrentEnforcementCompletionTest extends TestCase
{
    use RaceFlows, UsesConnections, UsesFlowTables;

    /** @var string The tenant whose enforcement changes. */
    private const string TENANT = 'tenant-1';

    /** @var string The protocol state the request was started with. */
    private const string STATE = 'the-protocol-state-of-the-enforced-completion';

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the request was started through. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The only connection the change allows. */
    private Connection $other;

    /** @var \Tests\Fixtures\Protocols\VerifyingDriver The driver the connections run over. */
    private VerifyingDriver $driver;

    /**
     * Skip where processes cannot share the database, then set up the features,
     * the connections, the request and the sessions.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpRace();
        $this->usePackageTables();
        $this->allowEveryAttempt();

        $this->driver = new VerifyingDriver;

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(SessionRevocation::class, new TableSessions);
        $this->app?->instance(Linker::class, new readonly class implements Linker {
            /**
             * One identity for every result.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
             * @return \SineMacula\Laravel\Sso\Links\LinkResolution
             */
            #[\Override]
            public function resolve(VerifiedResult $result, ClientContext $client): LinkResolution
            {
                unset($result);

                return ExampleLinks::resolution(new IdentityReference('App\Models\User', '42'));
            }
        });

        Config::set('sso.features.oidc', true);
        Config::set('sso.features.enforcement', true);
        Config::set('sso.applications', ['web' => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true]]);

        $driver = $this->driver;

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        TableSessions::create();

        $usable = [
            'tenant_id'             => self::TENANT,
            'protocol'              => VerifyingDriver::NAME,
            'enabled'               => true,
            'has_completed_sign_in' => true,
            'settings'              => ['issuer' => VerifyingDriver::ISSUER],
        ];

        $this->connection = $this->makeConnection($usable);
        $this->other      = $this->makeConnection($usable);

        $this->makeAuthorizationRequest($this->connection, [
            'state_digest'      => hash('sha256', self::STATE),
            'handoff_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        ]);
    }

    /**
     * Remove what the race used and drop the sessions table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->tearDownRace();

        TableSessions::drop();

        parent::tearDown();
    }

    /**
     * Rows of `[whether the completion holds first, whether a rule is stored,
     * whether the change read first]`.
     *
     * @return iterable<string, array{0: bool, 1: bool, 2: bool}>
     */
    public static function provideRaces(): iterable
    {
        foreach (['a stored rule' => true, 'no row' => false] as $row => $stored) {
            yield "the completion holding first, {$row}" => [true, $stored, false];
            yield "the completion holding first, {$row}, the change reading first" => [true, $stored, true];
            yield "the change holding first, {$row}" => [false, $stored, false];
        }
    }

    /**
     * A completion racing an enforcement change issues a code only under the
     * rule it locked.
     *
     * @param  bool  $completionFirst
     * @param  bool  $stored
     * @param  bool  $reads
     * @return void
     */
    #[DataProvider('provideRaces')]
    public function testACompletionRacingAnEnforcementChangeSeesTheCommittedRule(bool $completionFirst, bool $stored, bool $reads): void
    {
        if ($stored) {
            self::assertTrue($this->service()->update(self::TENANT, false, [$this->other->id], Clients::browser())->isChanged());
        }

        $reports = $this->race([
            function () use ($completionFirst): string {

                if ($completionFirst) {
                    $this->pauseBeforeCommit(self::onTable('insert', StorageConnection::table('handoff_codes.table')), function (): void {
                        $this->holdUntilBlocked();
                    });
                } else {
                    $this->driver->onComplete = function (): void {
                        $this->awaitSignal(self::HOLDS);
                    };
                }

                return $this->completed();
            },
            function () use ($completionFirst): string {

                if (!$completionFirst) {
                    return $this->holdThenCommit($this->enabled(...));
                }

                $this->awaitSignal(self::HOLDS);

                $status = $this->enabled();

                $this->commitSnapshot();

                return $status;
            },
        ], null, $this->snapshotsFor([false, $reads], self::reads(...)));

        $reported = (string) json_encode($reports);

        self::assertFalse(self::assertRacerEnded($reports[0], false), $reported);
        self::assertSame($completionFirst ? 'completed:-' : 'failed:enforcement_unsatisfied', $reports[0]['result'], $reported);
        self::assertSame($completionFirst ? 1 : 0, HandoffCode::query()->count(), $reported);
        self::assertNotNull(AuthorizationRequest::query()->sole()->completed_at, $reported);

        if (self::assertRacerEnded($reports[1], $completionFirst && $reads)) {
            return;
        }

        self::assertSame('updated', $reports[1]['result'], $reported);
        self::assertSame([$this->other->id], (new EnforcementFinder)->find(self::TENANT)?->connection_ids, $reported);
    }

    /**
     * Read every table the race touches, pinning a snapshot.
     *
     * @return void
     */
    private static function reads(): void
    {
        TenantEnforcement::query()->get();
        Connection::query()->get();
        HandoffCode::query()->get();
    }

    /**
     * Complete at the callback and report the status and reason.
     *
     * @return string
     */
    private function completed(): string
    {
        $result = app(CompletionService::class)->complete(
            CompletionEndpoint::CALLBACK,
            $this->connection->id,
            new CompletionRequest('GET', 'state=' . self::STATE, []),
            Clients::browser(),
        );

        return $result->status->value . ':' . ($result->reason->value ?? '-');
    }

    /**
     * Turn enforcement on with only the other connection and report the status.
     *
     * @return string
     */
    private function enabled(): string
    {
        return $this->service()->update(self::TENANT, true, [$this->other->id], Clients::browser())->status->value;
    }

    /**
     * The enforcement helper, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementService
     */
    private function service(): EnforcementService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(EnforcementService::class);
    }
}
