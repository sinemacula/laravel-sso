<?php

declare(strict_types = 1);

namespace Tests\Feature\Handoffs;

use Carbon\CarbonImmutable;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Enforcement;
use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Handoffs\RecheckLock;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\RecordsLockOrder;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesEnforcement;
use Tests\Fixtures\Enforcement\ScriptedInheritance;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Protocols\VerifyingDriver;
use Tests\TestCase;

/**
 * Feature tests for the recheck an adapter makes when it redeems its own codes
 * (SSO-4.3, SSO-4.6, SSO-8.5, SSO-9.9, decision D5): each outcome and the order
 * of the checks, a connection gone, disabled, incomplete, of another tenant or
 * over a protocol no longer registered; enforcement satisfied and not; a link
 * unchanged, removed, reassigned and added; a `LogicException` outside a
 * transaction on the storage connection or under another result's lock; the
 * locks taken in the package's order (the enforcement row, inserted
 * unconfigured when the tenant has none, then the connections in ascending id
 * order) under the default contract with the feature on, the connection alone
 * otherwise, with no enforcement statement and no inheritance asked while the
 * feature is off; an enforcing tenant that moved since the lock; and the
 * acknowledgement of a completed sign-in, written once, only for a `sign_in`
 * result, and undone with the redeemer's transaction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffRecheck::class)]
#[CoversClass(RecheckLock::class)]
#[CoversClass(RecheckOutcome::class)]
final class HandoffRecheckTest extends TestCase
{
    use RecordsLockOrder, UsesConnections, UsesEnforcement;

    /** @var string What a call outside the redeemer's transaction is told. */
    private const string NO_TRANSACTION = 'A handoff is rechecked inside the redeemer\'s transaction on the package\'s storage connection (decision D5).';

    /** @var string What a call under another result's lock is told. */
    private const string OTHER_LOCK = 'A handoff is rechecked under the lock taken for its result\'s tenant, connection and application.';

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Models\Connection A usable connection of `tenant-1`. */
    private Connection $connection;

    /** @var ?\SineMacula\Laravel\Sso\Identities\IdentityReference What the linker answers now. */
    private ?IdentityReference $linked = null;

    /** @var int How many times the linker was asked. */
    private int $linkerAsked = 0;

    /**
     * Bind a fixed clock and a linker answering the linked identity, register
     * the driver, and create the tables and a usable connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock  = new FixedClock('2026-11-01T09:30:00Z');
        $this->linked = new IdentityReference('App\Models\User', '42');

        $this->app?->instance(Clock::class, $this->clock);
        $resolve = function (): ?IdentityReference {
            $this->linkerAsked++;

            return $this->linked;
        };

        $this->app?->instance(Linker::class, new readonly class ($resolve) implements Linker {
            /**
             * Constructor.
             *
             * @param  \Closure(): ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $resolve
             */
            public function __construct(

                /** What every result resolves to. */
                private \Closure $resolve,
            ) {}

            /**
             * What the closure answers.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @return ?\SineMacula\Laravel\Sso\Identities\IdentityReference
             */
            #[\Override]
            public function resolve(VerifiedResult $result): ?IdentityReference
            {
                unset($result);

                return ($this->resolve)();
            }
        });

        $driver = new VerifyingDriver;

        config()->set('sso.features.oidc', true);

        app(ProtocolManager::class)->extend(VerifyingDriver::NAME, fn (): VerifyingDriver => $driver);

        $this->createConnectionTables();
        $this->createEnforcementTable();

        $this->connection = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'enabled' => true, 'settings' => ['issuer' => VerifyingDriver::ISSUER]]);
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropEnforcementTable();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * A usable connection that satisfies its tenant's enforcement, with a
     * result still linked to the same identity, passes, the linker asked once.
     *
     * @return void
     */
    public function testARecheckPasses(): void
    {
        self::assertSame(RecheckOutcome::PASSED, $this->recheck($this->verifiedResult(), new IdentityReference('App\Models\User', '42')));
        self::assertSame(1, $this->linkerAsked);
    }

    /**
     * A result linked to nothing at completion, and still linked to nothing,
     * passes.
     *
     * @return void
     */
    public function testAResultStillLinkedToNothingPasses(): void
    {
        $this->linked = null;

        self::assertSame(RecheckOutcome::PASSED, $this->recheck($this->verifiedResult(), null));
    }

    /**
     * How a connection may no longer be usable.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function unusableConnections(): iterable
    {
        foreach (['gone', 'disabled', 'incomplete', 'unregistered', 'of another tenant'] as $change) {
            yield $change => [$change];
        }
    }

    /**
     * A connection gone, disabled, incomplete, of another tenant than the
     * result names, or over a protocol no longer registered is
     * `connection_unavailable`, before enforcement or the link is asked.
     *
     * @param  string  $change
     * @return void
     */
    #[DataProvider('unusableConnections')]
    public function testAConnectionNoLongerUsable(string $change): void
    {
        $result = $this->verifiedResult();

        match ($change) {
            'gone'         => $this->connection->delete(),
            'disabled'     => $this->connection->forceFill(['enabled' => false])->save(),
            'incomplete'   => $this->connection->forceFill(['settings' => []])->save(),
            'unregistered' => $this->connection->forceFill(['protocol' => 'unregistered'])->saveQuietly(),
            default        => $result = $this->verifiedResult(tenantId: 'tenant-2'),
        };

        $asked = $this->bindRecordingEnforcement(EnforcementPolicy::notRequired('tenant-1', 'tenant-1'));

        self::assertSame(RecheckOutcome::CONNECTION_UNAVAILABLE, $this->recheck($result, new IdentityReference('App\Models\User', '42')));
        self::assertSame([], $asked->getArrayCopy());
        self::assertSame(0, $this->linkerAsked);
    }

    /**
     * A tenant whose enforcement requires other connections is
     * `enforcement_unsatisfied`, before the link is asked; one whose
     * enforcement includes the connection passes. Enforcement is asked for the
     * connection's tenant on the result's application.
     *
     * @return void
     */
    public function testEnforcement(): void
    {
        config()->set('sso.features.enforcement', true);

        $other       = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'enabled' => true, 'settings' => ['issuer' => VerifyingDriver::ISSUER]]);
        $enforcement = $this->makeEnforcement(['enabled' => true, 'connection_ids' => [$other->id]]);

        self::assertSame(RecheckOutcome::ENFORCEMENT_UNSATISFIED, $this->recheck($this->verifiedResult(), null));
        self::assertSame(0, $this->linkerAsked);

        $enforcement->forceFill(['connection_ids' => [$this->connection->id]])->save();

        self::assertSame(RecheckOutcome::PASSED, $this->recheck($this->verifiedResult(), new IdentityReference('App\Models\User', '42')));

        $asked = $this->bindRecordingEnforcement(EnforcementPolicy::required('tenant-1', 'tenant-1', [$this->connection->id], 'version-2'));

        self::assertSame(RecheckOutcome::PASSED, $this->recheck($this->verifiedResult(application: 'mobile'), new IdentityReference('App\Models\User', '42')));
        self::assertSame([['tenant-1', 'mobile']], $asked->getArrayCopy());
    }

    /**
     * How a link may have changed since completion.
     *
     * @return iterable<string, array{0: ?\SineMacula\Laravel\Sso\Identities\IdentityReference, 1: ?\SineMacula\Laravel\Sso\Identities\IdentityReference}>
     */
    public static function linkChanges(): iterable
    {
        $user = new IdentityReference('App\Models\User', '42');

        yield 'removed' => [$user, null];
        yield 'reassigned to another id' => [$user, new IdentityReference('App\Models\User', '43')];
        yield 'reassigned to another type' => [$user, new IdentityReference('App\Models\Admin', '42')];
        yield 'added' => [null, $user];
    }

    /**
     * A link removed, reassigned, or added where there was none since
     * completion is `link_changed`.
     *
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $atCompletion
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $now
     * @return void
     */
    #[DataProvider('linkChanges')]
    public function testALinkChangedSinceCompletion(?IdentityReference $atCompletion, ?IdentityReference $now): void
    {
        $this->linked = $now;

        self::assertSame(RecheckOutcome::LINK_CHANGED, $this->recheck($this->verifiedResult(), $atCompletion));
        self::assertSame(1, $this->linkerAsked);
    }

    /**
     * Outside a transaction on the storage connection, taking the lock is a
     * `LogicException`, and so is a recheck under a lock its transaction no
     * longer holds; nothing is asked.
     *
     * @return void
     */
    public function testARecheckOutsideATransactionIsALogicException(): void
    {
        $recheck = $this->rechecker();

        $calls = [
            fn (): RecheckLock => $recheck->lock('tenant-1', $this->connection->id, 'web'),
            fn (): RecheckOutcome => $recheck->recheck($this->verifiedResult(), null, $this->withinTransaction(fn (): RecheckLock => $this->lockFor($this->verifiedResult()))),
        ];

        foreach ($calls as $call) {

            try {
                $call();

                self::fail('A recheck ran outside a transaction.');
            } catch (\LogicException $exception) {
                self::assertSame(self::NO_TRANSACTION, $exception->getMessage());
            }
        }

        self::assertSame(0, $this->linkerAsked);
    }

    /**
     * Rows of `[tenant, application, connection]`: a lock taken for another
     * tenant, application or connection than the result names.
     *
     * @return iterable<string, array{0: string, 1: string, 2: ?string}>
     */
    public static function provideOtherLocks(): iterable
    {
        yield 'another tenant' => ['tenant-2', 'web', null];
        yield 'another application' => ['tenant-1', 'mobile', null];
        yield 'another connection' => ['tenant-1', 'web', '01jbotherconnection0000000'];
    }

    /**
     * A recheck or an acknowledgement under a lock taken for another tenant,
     * application or connection than the result's is a `LogicException`, and
     * nothing is asked or written.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @param  ?string  $connectionId
     * @return void
     */
    #[DataProvider('provideOtherLocks')]
    public function testARecheckUnderAnotherResultsLockIsALogicException(string $tenantId, string $application, ?string $connectionId): void
    {
        $recheck = $this->rechecker();

        foreach (['recheck', 'acknowledge'] as $call) {

            try {
                $this->withinTransaction(function () use ($recheck, $tenantId, $application, $connectionId, $call): void {

                    $lock = $recheck->lock($tenantId, $connectionId ?? $this->connection->id, $application);

                    $call === 'recheck'
                        ? $recheck->recheck($this->verifiedResult(), null, $lock)
                        : $recheck->acknowledgeSignIn($this->verifiedResult(), $lock);
                });

                self::fail('A recheck ran under another result\'s lock.');
            } catch (\LogicException $exception) {
                self::assertSame(self::OTHER_LOCK, $exception->getMessage());
            }
        }

        self::assertSame(0, $this->linkerAsked);
        self::assertFalse($this->reloaded()->has_completed_sign_in);
    }

    /**
     * With the feature on and the default contract, the lock takes the tenant's
     * enforcement row first (inserting it unconfigured when it has none), then
     * the connection and the rule's connections in one statement in ascending
     * id order; the recheck judges the locked rows and locks nothing more.
     *
     * @return void
     */
    public function testTheLockTakesTheEnforcementThenTheConnectionsInIdOrder(): void
    {
        config()->set('sso.features.enforcement', true);

        $before = $this->makeConnection(['id' => '00000000000000000000000000', 'protocol' => VerifyingDriver::NAME, 'enabled' => true]);
        $after  = $this->makeConnection(['id' => 'zzzzzzzzzzzzzzzzzzzzzzzzzz', 'protocol' => VerifyingDriver::NAME, 'enabled' => true]);

        $this->makeEnforcement(['enabled' => true, 'connection_ids' => [$after->id, $this->connection->id, $before->id]]);
        $this->recordLockOrder();

        self::assertSame(RecheckOutcome::PASSED, $this->recheck($this->verifiedResult(), new IdentityReference('App\Models\User', '42')));
        self::assertSame(['enforcement upsert', 'enforcement', 'connections ' . implode(', ', [$before->id, $this->connection->id, $after->id])], $this->lockOrder());
    }

    /**
     * A tenant with no rule stored has an unconfigured row inserted to lock,
     * which requires nothing; the lock then takes only the connection.
     *
     * @return void
     */
    public function testATenantWithNoRuleIsLockedThroughAnUnconfiguredRow(): void
    {
        config()->set('sso.features.enforcement', true);

        $this->recordLockOrder();

        self::assertSame(RecheckOutcome::PASSED, $this->recheck($this->verifiedResult(), new IdentityReference('App\Models\User', '42')));
        self::assertSame(['enforcement upsert', 'enforcement', 'connections ' . $this->connection->id], $this->lockOrder());

        $row = TenantEnforcement::query()->sole();

        self::assertSame('tenant-1', $row->tenant_id);
        self::assertNull($row->version);
        self::assertNull($row->changed_at);
        self::assertFalse($row->enabled);
        self::assertSame([], $row->connection_ids);
    }

    /**
     * With the feature off, the lock takes the connection alone: no statement
     * names the enforcement table, no row is inserted and the inheritance
     * contract is never asked.
     *
     * @return void
     */
    public function testWithTheFeatureOffNoEnforcementIsLockedOrAsked(): void
    {
        $inheritance = new ScriptedInheritance(['tenant-1']);

        $this->app?->instance(EnforcementInheritance::class, $inheritance);
        $this->recordLockOrder();

        self::assertSame(RecheckOutcome::PASSED, $this->recheck($this->verifiedResult(), new IdentityReference('App\Models\User', '42')));
        self::assertSame(['connections ' . $this->connection->id . ', tenant-1'], $this->lockOrder());
        self::assertSame(0, $this->enforcementStatements());
        self::assertSame(0, TenantEnforcement::query()->count());
        self::assertSame([], $inheritance->asked());
    }

    /**
     * Under another enforcement contract, the lock takes the connection alone
     * and the contract is asked at the recheck, as it is bound.
     *
     * @return void
     */
    public function testAnotherContractIsAskedAndNothingOfTheDefaultIsLocked(): void
    {
        config()->set('sso.features.enforcement', true);

        $asked = $this->bindRecordingEnforcement(EnforcementPolicy::required('tenant-1', 'tenant-1', ['01jbotherconnection0000000'], 'version-2'));

        $this->recordLockOrder();

        self::assertSame(RecheckOutcome::ENFORCEMENT_UNSATISFIED, $this->recheck($this->verifiedResult(), null));
        self::assertSame(['connections ' . $this->connection->id . ', tenant-1'], $this->lockOrder());
        self::assertSame(0, $this->enforcementStatements());
        self::assertSame([['tenant-1', 'web']], $asked->getArrayCopy());
    }

    /**
     * An inheritance contract that names another enforcing tenant by the
     * recheck than when the lock was taken is `connection_unavailable`: the
     * other tenant's rule is never locked out of order, and the link is not
     * asked.
     *
     * @return void
     */
    public function testAnEnforcingTenantThatMovedSinceTheLockIsConnectionUnavailable(): void
    {
        config()->set('sso.features.enforcement', true);

        $inheritance = new ScriptedInheritance(['tenant-1', 'parent-1']);

        $this->app?->instance(EnforcementInheritance::class, $inheritance);
        $this->recordLockOrder();

        self::assertSame(RecheckOutcome::CONNECTION_UNAVAILABLE, $this->recheck($this->verifiedResult(), null));
        self::assertSame([['tenant-1', 'web'], ['tenant-1', 'web']], $inheritance->asked());
        self::assertSame(['enforcement upsert', 'enforcement', 'connections ' . $this->connection->id], $this->lockOrder());
        self::assertSame(0, $this->linkerAsked);
    }

    /**
     * An inherited rule is the enforcing tenant's: its row is locked and its
     * connections judged, a connection of another tenant it names never
     * satisfying it.
     *
     * @return void
     */
    public function testAnInheritedRuleIsLockedAndJudged(): void
    {
        config()->set('sso.features.enforcement', true);

        $this->app?->instance(EnforcementInheritance::class, new ScriptedInheritance(['parent-1']));

        $parents = $this->makeConnection(['tenant_id' => 'parent-1', 'protocol' => VerifyingDriver::NAME, 'enabled' => true]);

        $this->makeEnforcement(['tenant_id' => 'parent-1', 'enabled' => true, 'connection_ids' => [$parents->id]]);

        self::assertSame(RecheckOutcome::ENFORCEMENT_UNSATISFIED, $this->recheck($this->verifiedResult(), null));

        TenantEnforcement::query()->sole()->forceFill(['connection_ids' => [$this->connection->id]])->save();

        self::assertSame(RecheckOutcome::ENFORCEMENT_UNSATISFIED, $this->recheck($this->verifiedResult(), null));

        TenantEnforcement::query()->sole()->forceFill(['enabled' => false])->save();

        self::assertSame(RecheckOutcome::PASSED, $this->recheck($this->verifiedResult(), new IdentityReference('App\Models\User', '42')));
    }

    /**
     * The connection's row is read with a locking read, once, where the
     * database has one.
     *
     * @return void
     */
    public function testTheConnectionIsReadLocked(): void
    {
        $database = DB::connection(StorageConnection::name());

        if ($database->getDriverName() === 'sqlite') {
            self::markTestSkipped('SQLite has no locking read.');
        }

        $statements = [];

        $database->listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = strtolower($query->sql);
        });

        $this->recheck($this->verifiedResult(), new IdentityReference('App\Models\User', '42'));

        $locked = array_filter($statements, static fn (string $sql): bool => str_contains($sql, StorageConnection::table('connections.table')) && str_contains($sql, 'for update'));

        self::assertCount(1, $locked);
    }

    /**
     * Acknowledging a `sign_in` result records the completed sign-in on its
     * connection, stamped now, inside the redeemer's transaction; a connection
     * that has one is not written again.
     *
     * @return void
     */
    public function testAcknowledgingASignIn(): void
    {
        $this->clock->advance(30);

        $this->withinTransaction(fn () => $this->acknowledge($this->verifiedResult()));

        $connection = $this->reloaded();

        self::assertTrue($connection->has_completed_sign_in);
        self::assertSame('2026-11-01T09:30:30+00:00', $connection->updated_at->toIso8601String());

        $this->clock->advance(30);

        $this->withinTransaction(fn () => $this->acknowledge($this->verifiedResult()));

        self::assertTrue($this->reloaded()->has_completed_sign_in);
        self::assertSame('2026-11-01T09:30:30+00:00', $this->reloaded()->updated_at->toIso8601String());
    }

    /**
     * An acknowledgement undone with the redeemer's transaction records
     * nothing.
     *
     * @return void
     */
    public function testAnAcknowledgementRolledBackRecordsNothing(): void
    {
        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        $this->acknowledge($this->verifiedResult());

        $database->rollBack();

        self::assertFalse($this->reloaded()->has_completed_sign_in);
    }

    /**
     * Purposes that never complete a sign-in.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Flows\Enums\Purpose}>
     */
    public static function otherPurposes(): iterable
    {
        yield 'link' => [Purpose::LINK];
        yield 'reauthenticate' => [Purpose::REAUTHENTICATE];
    }

    /**
     * A `link` or a `reauthenticate` result never completes a sign-in.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @return void
     */
    #[DataProvider('otherPurposes')]
    public function testOnlyASignInResultIsAcknowledged(Purpose $purpose): void
    {
        $database = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        try {
            $this->acknowledge($this->verifiedResult($purpose));

            self::fail('A result of another purpose was acknowledged.');
        } catch (\LogicException $exception) {
            self::assertSame(sprintf('Only a [sign_in] result completes a sign-in, not a [%s] one.', $purpose->value), $exception->getMessage());
        } finally {
            $database->rollBack();
        }

        self::assertFalse($this->reloaded()->has_completed_sign_in);
    }

    /**
     * Outside a transaction on the storage connection, acknowledging is a
     * `LogicException`, and records nothing.
     *
     * @return void
     */
    public function testAcknowledgingOutsideATransactionIsALogicException(): void
    {
        $lock = $this->withinTransaction(fn (): RecheckLock => $this->lockFor($this->verifiedResult()));

        try {
            $this->rechecker()->acknowledgeSignIn($this->verifiedResult(), $lock);

            self::fail('A sign-in was acknowledged outside a transaction.');
        } catch (\LogicException $exception) {
            self::assertSame(self::NO_TRANSACTION, $exception->getMessage());
        }

        self::assertFalse($this->reloaded()->has_completed_sign_in);
    }

    /**
     * Acknowledging through a connection gone, or of another tenant, is a
     * `LogicException`.
     *
     * @return void
     */
    public function testAcknowledgingThroughAConnectionGoneIsALogicException(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The connection a sign-in is acknowledged through is gone: recheck the handoff first.');

        $this->withinTransaction(fn () => $this->acknowledge($this->verifiedResult(tenantId: 'tenant-2')));
    }

    /**
     * Take the lock for the result and recheck it under the lock, inside a
     * transaction on the storage connection.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $linkedIdentity
     * @return \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome
     *
     * @throws \LogicException
     */
    private function recheck(VerifiedResult $result, ?IdentityReference $linkedIdentity): RecheckOutcome
    {
        return $this->withinTransaction(fn (): RecheckOutcome => $this->rechecker()->recheck($result, $linkedIdentity, $this->lockFor($result)));
    }

    /**
     * Take the lock for the result and acknowledge its sign-in under it, in the
     * transaction open.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return void
     *
     * @throws \LogicException
     */
    private function acknowledge(VerifiedResult $result): void
    {
        $this->rechecker()->acknowledgeSignIn($result, $this->lockFor($result));
    }

    /**
     * The lock for the result's tenant, connection and application, taken in
     * the transaction open.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return \SineMacula\Laravel\Sso\Handoffs\RecheckLock
     *
     * @throws \LogicException
     */
    private function lockFor(VerifiedResult $result): RecheckLock
    {
        return $this->rechecker()->lock($result->tenantId, $result->connectionId, $result->application);
    }

    /**
     * The recheck, as the container builds it now.
     *
     * @return \SineMacula\Laravel\Sso\Handoffs\HandoffRecheck
     */
    private function rechecker(): HandoffRecheck
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(HandoffRecheck::class);
    }

    /**
     * Run the callback inside a transaction on the storage connection.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $callback
     * @return TResult
     *
     * @throws \LogicException
     */
    private function withinTransaction(\Closure $callback): mixed
    {
        return DB::connection(StorageConnection::name())->transaction($callback);
    }

    /**
     * Bind an enforcement contract answering the policy, and answer the list
     * each question it is asked is recorded in.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
     * @return \ArrayObject<int, array{0: string, 1: string}>
     */
    private function bindRecordingEnforcement(EnforcementPolicy $policy): \ArrayObject
    {
        /** @var \ArrayObject<int, array{0: string, 1: string}> $asked */
        $asked = new \ArrayObject;

        $this->app?->instance(Enforcement::class, new readonly class ($policy, $asked) implements Enforcement {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy  $policy
             * @param  \ArrayObject<int, array{0: string, 1: string}>  $asked
             */
            public function __construct(

                /** What every question is answered. */
                private EnforcementPolicy $policy,

                /** Each tenant and application asked about. */
                private \ArrayObject $asked,
            ) {}

            /**
             * The policy given, recording the question.
             *
             * @param  string  $tenantId
             * @param  string  $application
             * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy
             */
            #[\Override]
            public function policy(string $tenantId, string $application): EnforcementPolicy
            {
                $this->asked->append([$tenantId, $application]);

                return $this->policy;
            }
        });

        return $asked;
    }

    /**
     * A verified result through the connection, of the tenant, for the
     * application and the purpose.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $tenantId
     * @param  string  $application
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    private function verifiedResult(Purpose $purpose = Purpose::SIGN_IN, string $tenantId = 'tenant-1', string $application = 'web'): VerifiedResult
    {
        return new VerifiedResult(
            issuer: VerifyingDriver::ISSUER,
            subject: VerifyingDriver::SUBJECT,
            nameIdFormat: null,
            connectionId: $this->connection->id,
            tenantId: $tenantId,
            protocol: VerifyingDriver::NAME,
            application: $application,
            purpose: $purpose,
            requestReference: RequestReference::fromString('Cq8tVv3w0kLmNoPqRsTuVwXyZ0123456'),
            attributes: [],
            emailDomainVerified: false,
            authenticationContext: new AuthenticationContext(CarbonImmutable::parse('2026-11-01T09:29:00Z'), ['pwd']),
        );
    }

    /**
     * The connection, read again.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function reloaded(): Connection
    {
        return Connection::query()->whereKey($this->connection->id)->sole();
    }
}
