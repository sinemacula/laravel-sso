<?php

declare(strict_types = 1);

namespace Tests\Integration\Handoffs;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Handoffs\DatabaseHandoffStore;
use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Links\ExampleLinks;
use Tests\Fixtures\Links\FixedLinker;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\TestCase;

/**
 * Integration tests for admitting a redemption with the package's tables on a
 * connection of their own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffRedemption::class)]
final class SeparateStorageRedemptionTest extends TestCase
{
    use UsesConnections;

    /** @var string The connection the package's tables are moved to. */
    private const string STORE = 'sso_handoff_store';

    /** @var string The client's verifier (RFC 7636, appendix B). */
    private const string VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference What the code is linked to. */
    private IdentityReference $linked;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection the code was issued through. */
    private Connection $connection;

    /**
     * Bind a fixed clock and a linker, and create the connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->linked = new IdentityReference('App\Models\User', '42');

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Linker::class, new FixedLinker($this->linked));

        $driver = new VerifyingDriver;

        config()->set('sso.features.oidc', true);

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'enabled' => true, 'settings' => ['issuer' => VerifyingDriver::ISSUER]]);
    }

    /**
     * A transaction on the default connection does not admit, and leaves the
     * code unspent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATransactionOnTheDefaultConnectionDoesNotAdmit(): void
    {
        self::assertNotSame(StorageConnection::name(), DB::getDefaultConnection());

        $code = $this->issue();

        try {
            DB::transaction(fn (): RedemptionResult => $this->admit($code));

            self::fail('A redemption was admitted outside a storage transaction.');
        } catch (\LogicException $exception) {
            self::assertSame('A session is admitted inside the caller\'s transaction on the package\'s storage connection.', $exception->getMessage());
        }

        self::assertNull($this->stored($code)->redeemed_at);
        self::assertSame(0, DB::connection(StorageConnection::name())->table(StorageConnection::table('single_use.table'))->count());
        self::assertTrue($this->admitted($code)->isRedeemed());
    }

    /**
     * A transaction on the storage connection admits.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATransactionOnTheStorageConnectionAdmits(): void
    {
        $code   = $this->issue();
        $answer = $this->admitted($code);

        self::assertTrue($answer->isAdmitted());
        self::assertSame($this->linked->jsonSerialize(), $answer->linkedIdentity?->jsonSerialize());
        self::assertNotNull($this->stored($code)->redeemed_at);
        self::assertSame(1, DB::connection(StorageConnection::name())->table(StorageConnection::table('single_use.table'))->count());
    }

    /**
     * Add the second connection, and move the storage connection to it.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        config()->set('database.connections.' . self::STORE, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        config()->set('sso.storage.connection', self::STORE);
    }

    /**
     * Issue a linked `sign_in` code for `web` bound to the client's verifier.
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
            linkedIdentity: $this->linked,
            linkId: ExampleLinks::linkId($this->linked),
        );

        return app(DatabaseHandoffStore::class)->issue($grant)->code->reveal();
    }

    /**
     * Admit the code as a `sign_in` for `web`, in a transaction on the storage
     * connection.
     *
     * @param  string  $code
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function admitted(string $code): RedemptionResult
    {
        return DB::connection(StorageConnection::name())->transaction(fn (): RedemptionResult => $this->admit($code));
    }

    /**
     * Admit the code as a `sign_in` for `web` through the connection.
     *
     * @param  string  $code
     * @return \SineMacula\Laravel\Sso\Handoffs\RedemptionResult
     */
    private function admit(string $code): RedemptionResult
    {
        return app(HandoffRedemption::class)->admit(Purpose::SIGN_IN, 'web', $this->connection->id, $code, self::VERIFIER, Clients::browser());
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
