<?php

declare(strict_types = 1);

namespace Tests\Integration\Combined;

use Carbon\CarbonImmutable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\InFlightVoider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainRechecker;
use SineMacula\Laravel\Sso\Domains\DomainWithdrawal;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Events\ConnectionDeleted;
use SineMacula\Laravel\Sso\Events\ConnectionDisabled;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\EnforcementChanged;
use SineMacula\Laravel\Sso\Events\KeyRetired;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RaceFlows;
use Tests\Feature\Linking\LinkingTestCase;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Keys\Certificates;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * What a failure rolls back of TA, an administrative change's one transaction,
 * on every database the suite runs on (SSO-2.11, SSO-4.5, SSO-10.5, SSO-11.4,
 * decision D5, `docs/design/transaction-ownership.md`): the change, what it
 * voids, what it withdraws and the session revocation it needs commit or roll
 * back together, and no event escapes.
 *
 * Each test names TA as what it rolls back, against a connection with a
 * verified domain, a live reservation and its code, a request in flight, an
 * active link and a trusted certificate, comparing every row stored before and
 * after. It adds the failure points `LifecycleRevocationTransactionTest` and
 * `EnforcementRevocationTransactionTest` miss, which pin a revocation that
 * writes and then throws: a statement of the change failing before and after
 * its mutations, the revocation's own statement, and the commit, after every
 * mutation. Then a domain's lapse whose withdrawal fails, and a trust change
 * whose voiding fails. The lease a recheck committed before its transaction is
 * outside TA, and is asserted to stay.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionLifecycle::class)]
#[CoversClass(ConnectionService::class)]
#[CoversClass(EnforcementService::class)]
#[CoversClass(KeyService::class)]
#[CoversClass(InFlightVoider::class)]
#[CoversClass(DomainRechecker::class)]
final class AdministrationRollbackTest extends LinkingTestCase
{
    use RaceFlows;

    /** @var string The table the revocation writes to, as an adapter writes its revoked sessions. */
    private const string REVOKED = 'combined_rollback_revocations';

    /** @var string The tenant whose connection it is. */
    private const string TENANT = 'tenant-1';

    /** @var string A connection's disable. */
    private const string DISABLE = 'disable';

    /** @var string A connection's deletion. */
    private const string DELETE = 'delete';

    /** @var string A tenant's enforcement turned on. */
    private const string ENFORCE = 'enforce';

    /** @var string A protocol trust change: a certificate no longer trusted. */
    private const string DISTRUST = 'distrust';

    /** @var string The certificate a trust change stops trusting. */
    private string $certificate = '';

    /**
     * Bind a fresh caller and a revocation that writes through the storage
     * connection; create its table and the enforcement table; and give the
     * connection what a change has to void, withdraw and delete: a reservation
     * and its code, a request in flight, an active link and a trusted
     * certificate. The connection has completed a sign-in, as turning
     * enforcement on needs.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(SessionRevocation::class, self::revocation());

        $this->usePackageTables();

        self::storageDatabase()->getSchemaBuilder()->create(self::REVOKED, static function (Blueprint $table): void {
            $table->id();
            $table->string('kind', 32);
            $table->string('tenant_id');
            $table->string('connection_id', 26)->nullable();
        });

        $this->start();

        self::assertTrue($this->complete()->isCompleted());
        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);

        $this->start();
        $this->makeLink($this->connection, 'another-subject', ['issuer' => VerifyingDriver::ISSUER]);

        $this->certificate = $this->trustedCertificate();

        $this->connection->forceFill(['has_completed_sign_in' => true])->save();

        $this->startRecordingEvents();
    }

    /**
     * Drop the tables made here.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::storageDatabase()->getSchemaBuilder()->dropIfExists(self::REVOKED);

        parent::tearDown();
    }

    /**
     * Rows of `[the change, the verb, the table, the occurrence]`, the verb
     * `null` for the commit: TA failed before and after each mutation, the
     * revocation's statement and the commit coming after every one.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: ?string, 3: int}>
     */
    public static function provideFailures(): iterable
    {
        yield 'a disable, at the switch' => [self::DISABLE, 'update', 'connections.table', 1];
        yield 'a disable, voiding the requests' => [self::DISABLE, 'update', 'authorization_requests.table', 1];
        yield 'a disable, voiding the codes' => [self::DISABLE, 'update', 'handoff_codes.table', 1];
        yield 'a disable, at the trust version' => [self::DISABLE, 'update', 'connections.table', 2];
        yield 'a disable, withdrawing the reservations' => [self::DISABLE, 'delete', 'links.table', 1];
        yield 'a disable, at the links version' => [self::DISABLE, 'update', 'connections.table', 3];
        yield 'a disable, at the revocation\'s write' => [self::DISABLE, 'insert', self::REVOKED, 1];
        yield 'a disable, at its commit' => [self::DISABLE, null, null, 1];

        yield 'a deletion, withdrawing the domain\'s reservations' => [self::DELETE, 'delete', 'links.table', 1];
        yield 'a deletion, voiding the requests' => [self::DELETE, 'update', 'authorization_requests.table', 1];
        yield 'a deletion, at the domains' => [self::DELETE, 'delete', 'domains.table', 1];
        yield 'a deletion, at the links' => [self::DELETE, 'delete', 'links.table', 3];
        yield 'a deletion, at the keys' => [self::DELETE, 'delete', 'keys.table', 1];
        yield 'a deletion, at the connection' => [self::DELETE, 'delete', 'connections.table', 1];
        yield 'a deletion, at the revocation\'s write' => [self::DELETE, 'insert', self::REVOKED, 1];
        yield 'a deletion, at its commit' => [self::DELETE, null, null, 1];

        yield 'an enforcement change, at the tenant\'s row' => [self::ENFORCE, 'insert', 'enforcement.table', 1];
        yield 'an enforcement change, at the rule' => [self::ENFORCE, 'update', 'enforcement.table', 1];
        yield 'an enforcement change, at the revocation\'s write' => [self::ENFORCE, 'insert', self::REVOKED, 1];
        yield 'an enforcement change, at its commit' => [self::ENFORCE, null, null, 1];

        yield 'a trust change, at the certificate' => [self::DISTRUST, 'delete', 'keys.table', 1];
        yield 'a trust change, voiding the requests' => [self::DISTRUST, 'update', 'authorization_requests.table', 1];
        yield 'a trust change, voiding the codes' => [self::DISTRUST, 'update', 'handoff_codes.table', 1];
        yield 'a trust change, at the trust version' => [self::DISTRUST, 'update', 'connections.table', 1];
        yield 'a trust change, withdrawing the reservations' => [self::DISTRUST, 'delete', 'links.table', 1];
        yield 'a trust change, at the links version' => [self::DISTRUST, 'update', 'connections.table', 2];
        yield 'a trust change, at its commit' => [self::DISTRUST, null, null, 1];
    }

    /**
     * Rolls back TA. Whichever statement fails, every row stands as it did,
     * nothing is voided, withdrawn or revoked, and no event is reported; the
     * change then goes through whole, reporting once.
     *
     * @param  string  $change
     * @param  ?string  $verb
     * @param  ?string  $table
     * @param  int  $occurrence
     * @return void
     */
    #[DataProvider('provideFailures')]
    public function testAFailureRollsTheChangeBackWhole(string $change, ?string $verb, ?string $table, int $occurrence): void
    {
        if ($change === self::ENFORCE) {
            config()->set('sso.features.enforcement', true);
        }

        $before = $this->stored();

        $this->armFailure($verb, $table, $occurrence);

        self::assertInjectedFailure(fn (): mixed => $this->changed($change));

        self::assertSame(1, $this->databaseFailuresFired());
        self::assertSame(0, self::storageDatabase()->transactionLevel());
        self::assertSame($before, $this->stored());
        $this->assertNoEvents();

        $this->changed($change);

        $this->assertEventSequence(self::eventsOf($change));
    }

    /**
     * Rows of `[the verb, the table's key]`, the verb `null` for the commit: TA
     * failed changing a rule already in force.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideLaterEnforcementFailures(): iterable
    {
        yield 'at the rule' => ['update', 'enforcement.table'];
        yield 'at the revocation\'s write' => ['insert', self::REVOKED];
        yield 'at its commit' => [null, null];
    }

    /**
     * Rolls back TA of a later enforcement change (SSO-4.5): the rule in force,
     * and the revocation an earlier change committed, stay; that earlier
     * change's event has been reported, and this one's never is.
     *
     * @param  ?string  $verb
     * @param  ?string  $table
     * @return void
     */
    #[DataProvider('provideLaterEnforcementFailures')]
    public function testALaterEnforcementChangeRollsBackAlone(?string $verb, ?string $table): void
    {
        config()->set('sso.features.enforcement', true);

        $this->changed(self::ENFORCE);

        $this->assertEventSequence([EnforcementChanged::class]);

        $second = $this->makeConnection(['enabled' => true, 'display_name' => 'Second']);
        $before = $this->stored();

        $this->startRecordingEvents();
        $this->armFailure($verb, $table);

        self::assertInjectedFailure(fn (): mixed => app(EnforcementService::class)->update(self::TENANT, true, [$this->connection->id, $second->id], Clients::browser()));

        self::assertSame($before, $this->stored());
        self::assertSame(1, self::storageDatabase()->table(self::REVOKED)->count());
        $this->assertNoEvents();
    }

    /**
     * Rows of `[the verb, the table's key, the occurrence]`, the verb `null`
     * for the commit: the lapse's transaction failed. The lease's update, and
     * its commit, are each the first of their kind, so the lapse's are the
     * second.
     *
     * @return iterable<string, array{0: ?string, 1: ?string, 2: int}>
     */
    public static function provideLapseFailures(): iterable
    {
        yield 'withdrawing the reservations' => ['delete', 'links.table', 1];
        yield 'at the links version' => ['update', 'connections.table', 1];
        yield 'at the lapse' => ['update', 'domains.table', 2];
        yield 'at its commit' => [null, null, 2];
    }

    /**
     * Rolls back TA of a domain's lapse: the reservation stands, the claim
     * stays verified and no `DomainLapsed` is reported. The recheck's lease
     * committed before TA opened, and stays.
     *
     * @param  ?string  $verb
     * @param  ?string  $table
     * @param  int  $occurrence
     * @return void
     */
    #[DataProvider('provideLapseFailures')]
    public function testADomainLapseWhoseWithdrawalFailsRollsBack(?string $verb, ?string $table, int $occurrence): void
    {
        $claim  = $this->lapsingClaim();
        $before = $this->stored(StorageConnection::table('domains.table'));

        $this->armFailure($verb, $table, $occurrence);

        self::assertInjectedFailure(static fn (): mixed => app(DomainRechecker::class)->recheck($claim, Clients::browser()));

        self::assertSame(1, $this->databaseFailuresFired());

        $this->assertLapseRolledBack($before);
    }

    /**
     * Rolls back TA of a domain's lapse, with the failure after the withdrawal
     * has deleted the reservation: it comes back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWithdrawalFailingAfterItsDeleteRollsItBack(): void
    {
        $claim   = $this->lapsingClaim();
        $before  = $this->stored(StorageConnection::table('domains.table'));
        $failure = new \RuntimeException('The withdrawal could not go on.');

        $this->app?->instance(DomainWithdrawal::class, new readonly class ($failure) extends DomainWithdrawal {
            /**
             * Constructor.
             *
             * @param  \RuntimeException  $failure
             */
            public function __construct(

                /** What it throws once it has deleted. */
                private \RuntimeException $failure,
            ) {}

            /**
             * Withdraw, then fail.
             *
             * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
             * @param  \SineMacula\Laravel\Sso\Models\Domain  $domain
             * @return void
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function linkingWithdrawn(Connection $connection, Domain $domain): void
            {
                parent::linkingWithdrawn($connection, $domain);

                throw $this->failure;
            }
        });

        try {
            app(DomainRechecker::class)->recheck($claim, Clients::browser());

            self::fail('The lapse went on.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        $this->assertLapseRolledBack($before);
    }

    /**
     * Rolls back TA of a trust change, with the failure after the voiding has
     * done everything it does: what it voided, the version it raised and the
     * reservations it deleted all come back, with the certificate, and nothing
     * is reported.
     *
     * @return void
     */
    public function testAVoidingFailingAfterItsWritesRollsTheTrustChangeBack(): void
    {
        $before  = $this->stored();
        $failure = new \RuntimeException('The voiding could not go on.');
        $clock   = app(Clock::class);

        $this->app?->instance(InFlightVoider::class, new readonly class ($clock, $failure) extends InFlightVoider {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
             * @param  \RuntimeException  $failure
             */
            public function __construct(

                // Not promoted: the parent keeps it
                Clock $clock,

                /** What it throws once it has voided. */
                private \RuntimeException $failure,
            ) {
                parent::__construct($clock);
            }

            /**
             * Void, then fail.
             *
             * @param  \SineMacula\Laravel\Sso\Models\Connection  $locked
             * @param  ?string  $spared
             * @return void
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function voidFor(Connection $locked, ?string $spared = null): void
            {
                parent::voidFor($locked, $spared);

                throw $this->failure;
            }
        });

        try {
            $this->changed(self::DISTRUST);

            self::fail('The trust change went on.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        self::assertSame($before, $this->stored());
        $this->assertNoEvents();
    }

    /**
     * Rows of `[the verb, the table's key, the occurrence]`, the verb `null`
     * for the commit: the trust change of a setting failed.
     *
     * @return iterable<string, array{0: ?string, 1: ?string, 2: int}>
     */
    public static function provideSettingFailures(): iterable
    {
        yield 'at the setting' => ['update', 'connections.table', 1];
        yield 'voiding the requests' => ['update', 'authorization_requests.table', 1];
        yield 'voiding the codes' => ['update', 'handoff_codes.table', 1];
        yield 'at the trust version' => ['update', 'connections.table', 2];
        yield 'at its commit' => [null, null, 1];
    }

    /**
     * Rolls back TA of a trust change made to a connection's settings: the
     * setting, what it voided and the version it raised all go back, and
     * `ConnectionUpdated` is reported only by the change that then commits.
     *
     * @param  ?string  $verb
     * @param  ?string  $table
     * @param  int  $occurrence
     * @return void
     */
    #[DataProvider('provideSettingFailures')]
    public function testASettingTrustChangeWhoseVoidingFailsRollsBack(?string $verb, ?string $table, int $occurrence): void
    {
        $changing = $this->makeConnection([
            'protocol'     => VerifyingDriver::NAME,
            'display_name' => 'Changing',
            'enabled'      => true,
            'settings'     => ['issuer' => VerifyingDriver::ISSUER],
        ]);

        $this->makeAuthorizationRequest($changing);
        $this->makeHandoffCode($changing);

        $before = $this->stored();
        $change = fn (): mixed => app(ConnectionService::class)->update(
            self::TENANT,
            $changing->id,
            ['settings' => ['issuer' => 'https://idp.example.com/moved']],
            Clients::browser(),
        );

        $this->armFailure($verb, $table, $occurrence);

        self::assertInjectedFailure($change);

        self::assertSame(1, $this->databaseFailuresFired());
        self::assertSame($before, $this->stored());
        $this->assertNoEvents();

        $change();

        $this->assertEventSequence([ConnectionUpdated::class]);
    }

    /**
     * Assert the lapse's transaction left nothing, and its lease stands.
     *
     * @param  array<string, list<string>>  $before
     * @return void
     */
    private function assertLapseRolledBack(array $before): void
    {
        self::assertSame(0, self::storageDatabase()->transactionLevel());
        self::assertSame($before, $this->stored(StorageConnection::table('domains.table')));

        $claim = Domain::query()->whereKey($this->domain->id)->sole();

        self::assertSame(DomainState::VERIFIED, $claim->state);
        self::assertSame('example.com', $claim->verified_domain);
        self::assertNull($claim->lapsed_at);
        self::assertNotNull($claim->recheck_leased_until);
        self::assertSame(1, Link::query()->where('state', LinkState::RESERVED->value)->count());
        $this->assertNoEvents();
    }

    /**
     * Make the change.
     *
     * @param  string  $change
     * @return mixed
     *
     * @throws \LogicException
     */
    private function changed(string $change): mixed
    {
        $id = $this->connection->id;

        return match ($change) {
            self::DISABLE  => app(ConnectionLifecycle::class)->disable(self::TENANT, $id, Clients::browser()),
            self::DELETE   => app(ConnectionLifecycle::class)->delete(self::TENANT, $id, Clients::browser()),
            self::ENFORCE  => app(EnforcementService::class)->update(self::TENANT, true, [$id], Clients::browser()),
            self::DISTRUST => app(KeyService::class)->distrustCertificate(self::TENANT, $id, $this->certificate, Clients::browser()),
            default        => throw new \LogicException(sprintf('No change is named [%s].', $change)),
        };
    }

    /**
     * What the change reports, once it commits.
     *
     * @param  string  $change
     * @return list<class-string<\SineMacula\Laravel\Sso\Contracts\SsoEvent>>
     *
     * @throws \LogicException
     */
    private static function eventsOf(string $change): array
    {
        return match ($change) {
            self::DISABLE  => [ConnectionDisabled::class],
            self::DELETE   => [ConnectionDeleted::class],
            self::ENFORCE  => [EnforcementChanged::class],
            self::DISTRUST => [KeyRetired::class],
            default        => throw new \LogicException(sprintf('No change is named [%s].', $change)),
        };
    }

    /**
     * The claim, whose grace has run out now, as a recheck reads it.
     *
     * @return \SineMacula\Laravel\Sso\Models\Domain
     */
    private function lapsingClaim(): Domain
    {
        $this->domain->forceFill(['lapses_at' => $this->clock->now()])->save();

        return Domain::query()->whereKey($this->domain->id)->sole();
    }

    /**
     * Every row stored, of the package's tables and the revocation's, but for
     * the table left out.
     *
     * @param  ?string  $without
     * @return array<string, list<string>>
     */
    private function stored(?string $without = null): array
    {
        $rows = self::storedRows([self::REVOKED]);

        unset($rows[(string) $without]);

        return $rows;
    }

    /**
     * A certificate the connection trusts, in this process.
     *
     * @return string
     */
    private function trustedCertificate(): string
    {
        $key = new ConnectionKey;

        $key->forceFill([
            'connection_id' => $this->connection->id,
            'use'           => KeyUse::IDP_SIGNING,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'public_key'    => (string) MaskedKey::fromCertificate(Certificates::distinct(50))->publicKey,
            'fingerprint'   => hash('sha256', 'the-trusted-certificate'),
            'not_after'     => CarbonImmutable::parse('2027-11-01T00:00:00Z'),
        ])->save();

        return $key->id;
    }

    /**
     * A revocation that records the scope through the storage connection,
     * inside the change's transaction.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\SessionRevocation
     */
    private static function revocation(): SessionRevocation
    {
        return new readonly class (self::REVOKED) implements SessionRevocation {
            /**
             * Constructor.
             *
             * @param  string  $table
             */
            public function __construct(

                /** The table it writes to. */
                private string $table,
            ) {}

            /**
             * Write the scope.
             *
             * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
             * @return void
             */
            #[\Override]
            public function revoke(RevocationScope $scope): void
            {
                DB::connection(StorageConnection::name())->table($this->table)->insert([
                    'kind'          => $scope->kind->value,
                    'tenant_id'     => $scope->tenantId,
                    'connection_id' => $scope->connectionId,
                ]);
            }
        };
    }
}
