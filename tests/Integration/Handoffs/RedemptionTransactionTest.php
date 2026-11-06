<?php

declare(strict_types = 1);

namespace Tests\Integration\Handoffs;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Links\ExampleLinks;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\TestCase;

/**
 * A redemption and the transaction it runs in (SSO-9.2, SSO-10.5, SSO-11.4,
 * decision D5): inside the caller's transaction on the storage connection it is
 * part of it, reported only once that commits, and undone, its consumption and
 * acknowledgement included, when it rolls back, a refusal as much as a
 * redemption; a linker that throws propagates, rolls the redemption back, and
 * reports nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffRedemption::class)]
final class RedemptionTransactionTest extends TestCase
{
    use RecordsEventSequences, UsesConnections;

    /** @var string The client's verifier (RFC 7636, appendix B). */
    private const string VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the code was issued through. */
    private Connection $connection;

    /** @var ?\Throwable What the linker throws, when set. */
    private ?\Throwable $linkerFailure = null;

    /**
     * Bind a fixed clock, a linker that links every result to one identity
     * unless it is set to throw, and a request from an IP address, register the
     * driver, create the tables and the connection, and start recording events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance('request', Request::create('/auth/sso/handoffs', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7']));
        $resolve = function (): IdentityReference {
            if ($this->linkerFailure !== null) {
                throw $this->linkerFailure;
            }

            return new IdentityReference('App\Models\User', '42');
        };

        $this->app?->instance(Linker::class, new readonly class ($resolve) implements Linker {
            /**
             * Constructor.
             *
             * @param  \Closure(): \SineMacula\Laravel\Sso\Identities\IdentityReference  $resolve
             */
            public function __construct(

                /** What every result resolves to. */
                private \Closure $resolve,
            ) {}

            /**
             * What the closure answers.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
             * @return \SineMacula\Laravel\Sso\Links\LinkResolution
             */
            #[\Override]
            public function resolve(VerifiedResult $result, ClientContext $client): LinkResolution
            {
                unset($result);

                return ExampleLinks::resolution(($this->resolve)());
            }
        });

        $driver = new VerifyingDriver;

        config()->set('sso.features.oidc', true);

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'enabled' => true, 'settings' => ['issuer' => VerifyingDriver::ISSUER]]);

        $this->startRecordingEvents();
    }

    /**
     * End any transaction a test left open.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $database = DB::connection(StorageConnection::name());

        while ($database->transactionLevel() > 0) {
            $database->rollBack();
        }

        parent::tearDown();
    }

    /**
     * A redemption inside the caller's transaction that rolls back is undone:
     * the code is unredeemed and unrecorded, no sign-in is acknowledged,
     * nothing is reported, and the code can still be redeemed.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARedemptionRolledBackWithTheCallersTransactionLeavesTheCodeUnredeemed(): void
    {
        $code     = $this->issue();
        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        self::assertTrue($this->redeem($code)->isRedeemed());
        self::assertSame(1, $database->transactionLevel());
        $this->assertNoEvents();

        $database->rollBack();

        $this->assertNoEvents();
        self::assertNull($this->stored($code)->redeemed_at);
        self::assertSame(0, DB::table(StorageConnection::table('single_use.table'))->count());
        self::assertFalse(Connection::query()->whereKey($this->connection->id)->sole()->has_completed_sign_in);

        self::assertTrue($this->redeem($code)->isRedeemed());

        $this->assertEventSequence([HandoffRedeemed::class]);
    }

    /**
     * A refusal inside the caller's transaction that rolls back reports
     * nothing, and its consumption is undone with it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARefusalRolledBackWithTheCallersTransactionReportsNothing(): void
    {
        $code     = $this->issue();
        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        self::assertSame(FailureReason::VERIFIER_MISMATCH, $this->redeem($code, 'another-clients-verifier-of-43-characters-0')->reason);

        $database->rollBack();

        $this->assertNoEvents();
        self::assertNull($this->stored($code)->redeemed_at);
        self::assertTrue($this->redeem($code)->isRedeemed());
    }

    /**
     * A redemption inside the caller's transaction is reported only once that
     * commits.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARedemptionInsideTheCallersTransactionIsReportedOnItsCommit(): void
    {
        $code     = $this->issue();
        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        self::assertTrue($this->redeem($code)->isRedeemed());

        $this->assertNoEvents();

        $database->commit();

        $this->assertEventSequence([HandoffRedeemed::class]);
        self::assertNotNull($this->stored($code)->redeemed_at);
        self::assertTrue(Connection::query()->whereKey($this->connection->id)->sole()->has_completed_sign_in);
    }

    /**
     * A linker that throws propagates: the redemption is rolled back, the code
     * stays unredeemed and unrecorded, and nothing is reported.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAThrowingLinkerPropagates(): void
    {
        $code = $this->issue();

        $this->linkerFailure = new \RuntimeException('The links cannot be read.');

        try {
            $this->redeem($code);

            self::fail('A linker that throws was answered.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The links cannot be read.', $exception->getMessage());
        }

        $this->assertNoEvents();
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        self::assertNull($this->stored($code)->redeemed_at);
        self::assertSame(0, DB::table(StorageConnection::table('single_use.table'))->count());
        self::assertFalse(Connection::query()->whereKey($this->connection->id)->sole()->has_completed_sign_in);
    }

    /**
     * A linker that throws inside the caller's transaction rolls back only the
     * redemption's savepoint: the caller's transaction stays open, and the code
     * unredeemed in it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAThrowingLinkerInsideTheCallersTransactionRollsBackItsSavepoint(): void
    {
        $code     = $this->issue();
        $database = DB::connection(StorageConnection::name());

        $this->linkerFailure = new \RuntimeException('The links cannot be read.');

        $database->beginTransaction();

        try {
            $this->redeem($code);

            self::fail('A linker that throws was answered.');
        } catch (\RuntimeException $exception) {
            self::assertSame($this->linkerFailure, $exception);
            self::assertSame(1, $database->transactionLevel());
            self::assertNull($this->stored($code)->redeemed_at);
        }

        $database->rollBack();

        $this->assertNoEvents();
    }

    /**
     * Issue a linked `sign_in` code for `web` through the connection, bound to
     * the client's verifier.
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
            tenantId: 'tenant-1',
            protocol: VerifyingDriver::NAME,
            application: 'web',
            purpose: Purpose::SIGN_IN,
            requestReference: RequestReference::fromString('Hq8tVv3w0kLmNoPqRsTuVwXyZ0123456'),
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
            linkId: 'link-42',
        );

        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(DatabaseHandoffStore::class)->issue($grant)->code->reveal();
    }

    /**
     * Redeem the code as a `sign_in` for `web` through the connection.
     *
     * @param  string  $code
     * @param  string  $verifier
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function redeem(string $code, string $verifier = self::VERIFIER): RedemptionResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $redemption = $app->make(HandoffRedemption::class);

        return DB::connection(StorageConnection::name())->transaction(
            fn (): RedemptionResult => $redemption->redeem(Purpose::SIGN_IN, 'web', $this->connection->id, $code, $verifier, Clients::browser()),
        );
    }

    /**
     * The stored row of the code, read again.
     *
     * @param  string  $code
     * @return \SineMacula\Laravel\Sso\Models\HandoffCode
     */
    private function stored(string $code): StoredCode
    {
        return StoredCode::query()->where('code_digest', hash('sha256', $code))->sole();
    }
}
