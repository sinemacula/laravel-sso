<?php

declare(strict_types = 1);

namespace Tests\Integration\Handoffs;

use Carbon\CarbonImmutable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\InFlightVoider;
use SineMacula\Laravel\Sso\Contracts\AttemptLimiter;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\RateLimiting\AttemptResult;
use SineMacula\Laravel\Sso\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RacesProcesses;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Links\ExampleLinks;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\Integration\Examples\RedeemingAHandoff\OwnHandoffCodes;
use Tests\Integration\Examples\RedeemingAHandoff\OwnHandoffRedemption;
use Tests\TestCase;

/**
 * Integration tests racing a trust change against redeeming an
 * application-issued code.
 *
 * The package never voids such a code, so only its stored trust version decides
 * it. Skipped on SQLite and without `pcntl`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffRecheck::class)]
#[CoversClass(InFlightVoider::class)]
final class TrustChangeRedemptionRaceTest extends TestCase
{
    use RacesProcesses, UsesConnections;

    /** @var string The tenant the connection belongs to. */
    private const string TENANT = 'tenant-1';

    /** @var string The client's verifier (RFC 7636, appendix B). */
    private const string VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    /** @var string The signal the change raises once it holds the connection's lock. */
    private const string CHANGE_LOCKED = 'change-locked';

    /** @var string The signal the redemption raises once it holds the connection's lock. */
    private const string REDEMPTION_LOCKED = 'redemption-locked';

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the code was issued through. */
    private Connection $connection;

    /** @var string The code the application's store issued. */
    private string $code;

    /** @var bool Whether the tables were made. */
    private bool $created = false;

    /**
     * Skip where processes cannot share the database, then set up the linker,
     * the signalling voider, the tables, the connection and the code.
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

        $clock = new FixedClock('2026-11-01T09:30:00Z');

        $this->app?->instance(Clock::class, $clock);
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(AttemptLimiter::class, new readonly class implements AttemptLimiter {
            /**
             * Allow every attempt.
             *
             * @param  \SineMacula\Laravel\Sso\RateLimiting\AttemptSubject  $subject
             * @return \SineMacula\Laravel\Sso\RateLimiting\AttemptResult
             */
            #[\Override]
            public function attempt(AttemptSubject $subject): AttemptResult
            {
                unset($subject);

                return AttemptResult::allowed();
            }
        });
        $this->linkerSignals(static function (): void {});
        $this->app?->instance(InFlightVoider::class, $this->signallingVoider($clock));

        config()->set('sso.features.oidc', true);

        $driver = new VerifyingDriver;

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        $this->usePackageTables();
        $this->createOwnCodesTable();

        $this->created    = true;
        $this->connection = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'enabled' => true, 'settings' => ['issuer' => VerifyingDriver::ISSUER]]);
        $this->code       = $this->issue();
    }

    /**
     * Remove what the race used and drop the application's code table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->tearDownRace();

        if ($this->created) {
            Schema::connection(StorageConnection::name())->dropIfExists(OwnHandoffCodes::TABLE);
        }

        parent::tearDown();
    }

    /**
     * With the change holding the lock first, the redemption is
     * `connection_unavailable`.
     *
     * @return void
     */
    public function testARedemptionWaitingOnATrustChangeIsRefused(): void
    {
        $this->assertChangeWins($this->race([$this->changer(), $this->redeemer(self::CHANGE_LOCKED)]));
    }

    /**
     * The same race, each process in a transaction that read the code first.
     *
     * @return void
     */
    public function testARedemptionWaitingOnATrustChangeInsideCallersTransactionsIsRefused(): void
    {
        $code = $this->code;

        $before = static function () use ($code): void {
            Connection::query()->get();
            app(OwnHandoffCodes::class)->find($code);
        };

        $this->assertChangeWins($this->race([$this->changer(), $this->redeemer(self::CHANGE_LOCKED)], StorageConnection::name(), $before));
    }

    /**
     * With the redemption holding the lock first, it is admitted and the change
     * follows.
     *
     * @return void
     */
    public function testATrustChangeWaitingOnARedemptionLetsItBeAdmitted(): void
    {
        $this->linkerSignals(fn () => $this->signal(self::REDEMPTION_LOCKED));

        $reports = $this->race([$this->redeemer(null), $this->changer(self::REDEMPTION_LOCKED)]);

        self::assertSame(['admitted', 'updated'], $this->assertRacersSucceeded($reports));
        self::assertSame(1, $this->trustVersion());
        self::assertNotNull($this->consumedAt());
    }

    /**
     * Assert the change raised the version once and the redemption was refused.
     *
     * On PostgreSQL the redemption may fail to serialise instead.
     *
     * @param  list<array{result: mixed, error: ?string}>  $reports
     * @return void
     */
    private function assertChangeWins(array $reports): void
    {
        $results = $this->assertRacersSucceeded($reports);

        self::assertSame('updated', $results[0]);
        self::assertSame(1, $this->trustVersion());

        if ($reports[1]['error'] === self::RACE_SERIALIZATION_FAILURE) {
            self::assertNull($this->consumedAt());

            return;
        }

        self::assertSame('connection_unavailable', $results[1]);
        self::assertNotNull($this->consumedAt());
    }

    /**
     * Wait for the signal, if any, change the connection's issuer and report.
     *
     * @param  ?string  $after
     * @return \Closure(): string
     */
    private function changer(?string $after = null): \Closure
    {
        $connectionId = $this->connection->id;

        return function () use ($connectionId, $after): string {

            if ($after !== null) {
                $this->awaitSignal($after);
            }

            return app(ConnectionService::class)->update(self::TENANT, $connectionId, ['settings' => ['issuer' => 'https://login.example.com']], Clients::browser())->status->value;
        };
    }

    /**
     * Wait for the signal, if any, redeem the application's code and report.
     *
     * @param  ?string  $after
     * @return \Closure(): string
     */
    private function redeemer(?string $after): \Closure
    {
        $code = $this->code;

        return function () use ($code, $after): string {

            if ($after !== null) {
                $this->awaitSignal($after);
            }

            return app(OwnHandoffRedemption::class)->redeem(Purpose::SIGN_IN, $code, self::VERIFIER, Clients::browser())->value ?? 'admitted';
        };
    }

    /**
     * Bind a linker that calls the closure each time the recheck asks it.
     *
     * @param  \Closure(): void  $asked
     * @return void
     */
    private function linkerSignals(\Closure $asked): void
    {
        $this->app?->instance(Linker::class, new readonly class ($asked) implements Linker {
            /**
             * Call the closure each time the linker is asked.
             *
             * @param  \Closure(): void  $asked
             */
            public function __construct(

                /** Called each time the linker is asked. */
                private \Closure $asked,
            ) {}

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

                ($this->asked)();

                return ExampleLinks::resolution(new IdentityReference('App\Models\User', '42'));
            }
        });
    }

    /**
     * A voider that signals once it has raised the version under the lock.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     * @return \SineMacula\Laravel\Sso\Connections\InFlightVoider
     */
    private function signallingVoider(Clock $clock): InFlightVoider
    {
        $signal = fn () => $this->signal(self::CHANGE_LOCKED);

        return new readonly class ($clock, $signal) extends InFlightVoider {
            /**
             * Signal once the void is made.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
             * @param  \Closure(): void  $signal
             */
            public function __construct(

                // Passed to the parent constructor
                Clock $clock,

                /** Called once the void is made. */
                private \Closure $signal,
            ) {
                parent::__construct($clock);
            }

            /**
             * Void the reservations, then signal.
             *
             * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
             * @return void
             */
            #[\Override]
            protected function reservationsVoided(Connection $locked): void
            {
                parent::reservationsVoided($locked);

                ($this->signal)();
            }
        };
    }

    /**
     * Create the application's table of codes, as its example creates it.
     *
     * @return void
     */
    private function createOwnCodesTable(): void
    {
        Schema::connection(StorageConnection::name())->create(OwnHandoffCodes::TABLE, static function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('code_digest', 64)->unique();
            $table->text('result');
            $table->string('challenge', 43);
            $table->string('linked_identity_type')->nullable();
            $table->string('linked_identity_id')->nullable();
            $table->string('link_id')->nullable();
            $table->string('identity_type')->nullable();
            $table->string('identity_id')->nullable();
            $table->string('session_id')->nullable();
            $table->string('reservation_id')->nullable();
            $table->unsignedBigInteger('trust_version');
            $table->unsignedBigInteger('session_not_after')->nullable();
            $table->unsignedBigInteger('expires_at');
            $table->unsignedBigInteger('consumed_at')->nullable();
        });
    }

    /**
     * Issue a linked `sign_in` code through the application's own store.
     *
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function issue(): string
    {
        $result = new VerifiedResult(
            issuer: VerifyingDriver::ISSUER,
            subject: VerifyingDriver::SUBJECT,
            nameIdFormat: null,
            connectionId: $this->connection->id,
            tenantId: self::TENANT,
            protocol: VerifyingDriver::NAME,
            application: 'web',
            purpose: Purpose::SIGN_IN,
            requestReference: RequestReference::fromString('Gq8tVv3w0kLmNoPqRsTuVwXyZ0123456'),
            attributes: [],
            emailDomainVerified: false,
            authenticationContext: new AuthenticationContext(CarbonImmutable::parse('2026-11-01T09:29:00Z'), ['pwd']),
        );

        $grant = new HandoffGrant(
            result: $result,
            challenge: S256Challenge::fromString('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'),
            expiresAt: CarbonImmutable::parse('2026-11-01T09:31:00Z'),
            trustVersion: $this->connection->trust_version,
            linkedIdentity: new IdentityReference('App\Models\User', '42'),
            linkId: ExampleLinks::linkId(new IdentityReference('App\Models\User', '42')),
        );

        return DB::connection(StorageConnection::name())->transaction(static fn (): string => app(OwnHandoffCodes::class)->issue($grant)->code->reveal());
    }

    /**
     * The connection's trust version, read again.
     *
     * @return int
     */
    private function trustVersion(): int
    {
        return Connection::query()->whereKey($this->connection->id)->sole()->trust_version;
    }

    /**
     * When the application's code was consumed, or `null`.
     *
     * @return mixed
     */
    private function consumedAt(): mixed
    {
        return DB::connection(StorageConnection::name())->table(OwnHandoffCodes::TABLE)->value('consumed_at');
    }
}
