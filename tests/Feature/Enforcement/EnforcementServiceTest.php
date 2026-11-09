<?php

declare(strict_types = 1);

namespace Tests\Feature\Enforcement;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Administration\EnforcementEvents;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Enforcement\EnforcementFinder;
use SineMacula\Laravel\Sso\Enforcement\EnforcementLock;
use SineMacula\Laravel\Sso\Enforcement\EnforcementResult;
use SineMacula\Laravel\Sso\Enforcement\EnforcementService;
use SineMacula\Laravel\Sso\Enforcement\EnforcementSummary;
use SineMacula\Laravel\Sso\Enforcement\Enums\EnforcementStatus;
use SineMacula\Laravel\Sso\Events\EnforcementChanged;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesEnforcement;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Enforcement\FailingRevocation;
use Tests\Fixtures\Enforcement\RecordingRevocation;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\TestCase;

/**
 * Feature tests for the enforcement helper (SSO-4.1, SSO-4.3, SSO-4.5,
 * SSO-2.11, SSO-2.12, SSO-10.3): every outcome and violation, another tenant's
 * connection answered as an unknown one, turning it on only with a completed
 * sign-in, freshness asked only for a change, a new version on every change,
 * the revocation called inside the change's transaction with the policy now in
 * force, and the one event each change reports; a refusal writes, revokes and
 * reports nothing, and a failed revocation rolls the change back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnforcementService::class)]
#[CoversClass(EnforcementFinder::class)]
#[CoversClass(EnforcementLock::class)]
#[CoversClass(EnforcementResult::class)]
#[CoversClass(EnforcementSummary::class)]
#[CoversClass(EnforcementEvents::class)]
final class EnforcementServiceTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesEnforcement;

    /** @var string The tenant whose enforcement the helper changes. */
    private const string TENANT = 'tenant-1';

    /** @var string An id no connection has. */
    private const string UNKNOWN_ID = '01jbzzzzzzzzzzzzzzzzzzzzzz';

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract the helper asks. */
    private RecordingFreshness $freshness;

    /** @var \Tests\Fixtures\Enforcement\RecordingRevocation The revocation the helper calls. */
    private RecordingRevocation $revocation;

    /** @var \SineMacula\Laravel\Sso\Identities\Caller Who makes each change. */
    private Caller $actor;

    /** @var \SineMacula\Laravel\Sso\Models\Connection An enabled connection of the tenant that has completed a sign-in. */
    private Connection $completed;

    /** @var \SineMacula\Laravel\Sso\Models\Connection An enabled connection of the tenant that has completed none. */
    private Connection $untried;

    /**
     * Bind the clock, the freshness contract and the revocation, create the
     * tables and the tenant's connections, switch the feature on and record
     * events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock      = new FixedClock('2026-11-01T09:30:00Z');
        $this->freshness  = new RecordingFreshness;
        $this->revocation = new RecordingRevocation;
        $this->actor      = new Caller(new IdentityReference('App\Models\User', '42'));

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Freshness::class, $this->freshness);
        $this->app?->instance(SessionRevocation::class, $this->revocation);

        $this->usePackageTables();

        Config::set('sso.features.enforcement', true);

        $this->completed = $this->makeConnection(['enabled' => true, 'has_completed_sign_in' => true]);
        $this->untried   = $this->makeConnection(['enabled' => true, 'has_completed_sign_in' => false]);

        $this->startRecordingEvents();
    }

    /**
     * Turning it on for the first time stores the rule with a new version, asks
     * freshness once, revokes once inside the transaction after the write, and
     * reports the change with no previous version.
     *
     * @return void
     */
    public function testTurningItOnStoresTheRuleRevokesAndReports(): void
    {
        $result = $this->turnOn([$this->completed->id, $this->untried->id]);

        $summary = self::summaryOf($result, EnforcementStatus::UPDATED);
        $ids     = self::sortedIds([$this->completed->id, $this->untried->id]);

        self::assertSame(self::TENANT, $summary->tenantId);
        self::assertTrue($summary->enabled);
        self::assertSame($ids, $summary->connectionIds);
        self::assertMatchesRegularExpression('/^[0-9a-hjkmnp-tv-z]{26}$/', (string) $summary->version);
        self::assertSame('2026-11-01T09:30:00+00:00', $summary->changedAt?->toIso8601String());
        self::assertSame([[FreshnessOperation::ENFORCEMENT_UPDATE, 300]], $this->freshness->asked());

        $stored = $this->stored();

        self::assertTrue($stored->enabled);
        self::assertSame($ids, $stored->connection_ids);
        self::assertSame($summary->version, $stored->version);

        $calls = $this->revocation->calls();

        self::assertCount(1, $calls);
        self::assertSame(1, $calls[0]['level']);
        self::assertSame($summary->version, $calls[0]['version']);

        $scope = $calls[0]['scope'];

        self::assertSame(RevocationScopeKind::TENANT, $scope->kind);
        self::assertSame(RevocationReason::ENFORCEMENT_CHANGED, $scope->reason);
        self::assertSame(self::TENANT, $scope->tenantId);
        self::assertSame(
            ['tenant_id' => self::TENANT, 'enforcing_tenant_id' => self::TENANT, 'required' => true, 'connection_ids' => $ids, 'version' => $summary->version],
            $scope->policy?->jsonSerialize(),
        );

        $this->assertEventSequence([EnforcementChanged::class]);

        $event = $this->changedEvent();

        self::assertTrue($event->enabled);
        self::assertSame($ids, $event->connectionIds);
        self::assertSame($summary->version, $event->version);
        self::assertNull($event->previousVersion);
        self::assertSame(self::TENANT, $event->context->connectionTenantId);
        self::assertNull($event->context->connectionId);
        self::assertSame('App\Models\User', $event->context->actingIdentityMorphClass);
        self::assertSame('42', $event->context->actingIdentityId);
    }

    /**
     * Only the enabled connections given satisfy the policy the revocation is
     * called with, though every one given is stored.
     *
     * @return void
     */
    public function testTheRevokedPolicyListsOnlyTheEnabledConnections(): void
    {
        $disabled = $this->makeConnection(['enabled' => false, 'has_completed_sign_in' => true]);

        $result = $this->turnOn([$disabled->id, $this->completed->id]);

        self::assertSame(self::sortedIds([$disabled->id, $this->completed->id]), self::summaryOf($result, EnforcementStatus::UPDATED)->connectionIds);
        self::assertSame([$this->completed->id], $this->revocation->scopes()[0]->policy?->connectionIds);
    }

    /**
     * Changing the connections while on revokes again, with the new version and
     * the new set, and reports the version it replaced.
     *
     * @return void
     */
    public function testChangingTheConnectionsWhileOnRevokesAgain(): void
    {
        $first  = self::summaryOf($this->turnOn([$this->completed->id]), EnforcementStatus::UPDATED);
        $second = self::summaryOf($this->turnOn([$this->completed->id, $this->untried->id]), EnforcementStatus::UPDATED);

        $scopes = $this->revocation->scopes();

        self::assertCount(2, $scopes);
        self::assertNotSame($first->version, $second->version);
        self::assertSame($second->version, $scopes[1]->policy?->version);
        self::assertSame(self::sortedIds([$this->completed->id, $this->untried->id]), $scopes[1]->policy?->connectionIds);

        $this->assertEventSequence([EnforcementChanged::class, EnforcementChanged::class]);

        self::assertSame($first->version, $this->changedEvent(1)->previousVersion);
    }

    /**
     * Turning it off revokes nothing, needs no completed sign-in, and reports
     * the change.
     *
     * @return void
     */
    public function testTurningItOffRevokesNothing(): void
    {
        $on  = self::summaryOf($this->turnOn([$this->completed->id]), EnforcementStatus::UPDATED);
        $off = self::summaryOf($this->service()->update(self::TENANT, false, [$this->untried->id], Clients::browser(), $this->actor), EnforcementStatus::UPDATED);

        self::assertFalse($off->enabled);
        self::assertSame([$this->untried->id], $off->connectionIds);
        self::assertCount(1, $this->revocation->calls());
        self::assertFalse($this->changedEvent(1)->enabled);
        self::assertSame($on->version, $this->changedEvent(1)->previousVersion);
        self::assertFalse($this->stored()->enabled);
    }

    /**
     * Storing a rule that is off for a tenant with none is a change, with no
     * previous version and no revocation.
     *
     * @return void
     */
    public function testStoringARuleThatIsOffIsAChange(): void
    {
        $summary = self::summaryOf($this->service()->update(self::TENANT, false, [$this->untried->id], Clients::browser()), EnforcementStatus::UPDATED);

        self::assertFalse($summary->enabled);
        self::assertNotNull($summary->version);
        self::assertSame([], $this->revocation->calls());
        self::assertNull($this->changedEvent()->previousVersion);
        self::assertNull($this->changedEvent()->context->actingIdentityId);
    }

    /**
     * Every change gives a new version, never one used before.
     *
     * @return void
     */
    public function testEveryChangeGivesANewVersion(): void
    {
        $changes = [
            [true, [$this->completed->id]],
            [false, [$this->completed->id]],
            [true, [$this->completed->id]],
            [true, [$this->completed->id, $this->untried->id]],
            [false, []],
        ];

        $versions = [];

        foreach ($changes as [$enabled, $ids]) {
            $versions[] = self::summaryOf($this->service()->update(self::TENANT, $enabled, $ids, Clients::browser()), EnforcementStatus::UPDATED)->version;
        }

        self::assertCount(5, array_unique($versions));
        $replaced = array_map(static fn (EnforcementChanged $event): ?string => $event->previousVersion, array_slice($this->changedEvents(), 1));

        self::assertSame(array_slice($versions, 0, 4), $replaced);
    }

    /**
     * Giving what is stored, the ids in any order and repeated, is unchanged:
     * nothing is asked, written, revoked or reported.
     *
     * @return void
     */
    public function testGivingWhatIsStoredIsUnchanged(): void
    {
        $stored = self::summaryOf($this->turnOn([$this->completed->id, $this->untried->id]), EnforcementStatus::UPDATED);

        $this->freshness->reset();
        $this->startRecordingEvents();
        $this->clock->advance(60);

        $result = $this->turnOn([$this->untried->id, $this->completed->id, $this->untried->id]);

        self::assertEquals($stored, self::summaryOf($result, EnforcementStatus::UNCHANGED));
        self::assertFalse($result->isChanged());
        self::assertSame([], $this->freshness->asked());
        self::assertCount(1, $this->revocation->calls());
        self::assertSame($stored->version, $this->stored()->version);
        $this->assertNoEvents();
    }

    /**
     * A rule that looked unchanged on the first read, but was turned off before
     * the lock (as a caller's older transaction snapshot would show it), is
     * changed under the lock once freshness is asked: the update is never lost
     * as `unchanged`.
     *
     * @return void
     */
    public function testARuleThatLookedUnchangedButChangedMeanwhileIsChanged(): void
    {
        $stored = self::summaryOf($this->turnOn([$this->completed->id]), EnforcementStatus::UPDATED);

        $this->freshness->reset();
        $this->turnOffAfterTheFirstRead();

        $result = $this->turnOn([$this->completed->id]);

        self::assertTrue(self::summaryOf($result, EnforcementStatus::UPDATED)->enabled);
        self::assertNotSame($stored->version, $this->stored()->version);
        self::assertTrue($this->stored()->enabled);
        self::assertSame([FreshnessOperation::ENFORCEMENT_UPDATE], $this->freshness->operations());
    }

    /**
     * A rule that looked unchanged but changed before the lock is refused, with
     * nothing written, when the caller then proves stale.
     *
     * @return void
     */
    public function testARuleThatChangedMeanwhileStillNeedsAFreshCaller(): void
    {
        self::summaryOf($this->turnOn([$this->completed->id]), EnforcementStatus::UPDATED);

        $this->freshness->answer(FreshnessOutcome::STALE);
        $this->turnOffAfterTheFirstRead();

        $result = $this->turnOn([$this->completed->id]);

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $result->reason);
        self::assertFalse($this->stored()->enabled);
    }

    /**
     * Turning off a tenant with no rule stored is unchanged, and stores no
     * rule: the only row is the unconfigured one the lock inserted, which reads
     * as none.
     *
     * @return void
     */
    public function testTurningOffATenantWithNoRuleIsUnchanged(): void
    {
        $result = $this->service()->update(self::TENANT, false, [], Clients::browser());

        self::assertEquals(new EnforcementSummary(self::TENANT, false, []), self::summaryOf($result, EnforcementStatus::UNCHANGED));
        $this->assertNoRuleStored();
        self::assertSame([], $this->freshness->asked());
        $this->assertNoEvents();
    }

    /**
     * Rows of `[enabled, ids, violations]`: connection ids refused, and the
     * violations each gives.
     *
     * @return iterable<string, array{bool, list<mixed>, list<array{setting: string, code: string}>}>
     */
    public static function provideViolations(): iterable
    {
        $tooMany = array_map(static fn (int $n): string => sprintf('01jb%022d', $n), range(1, EnforcementService::MAX_CONNECTIONS + 1));

        yield 'not a string' => [true, [7], [self::violation('connection_ids.0', ViolationCode::INVALID_TYPE)]];
        yield 'a list' => [false, [['01jb']], [self::violation('connection_ids.0', ViolationCode::INVALID_TYPE)]];
        yield 'empty' => [true, [''], [self::violation('connection_ids.0', ViolationCode::INVALID_FORMAT)]];
        yield 'too long' => [true, [str_repeat('0', 27)], [self::violation('connection_ids.0', ViolationCode::INVALID_FORMAT)]];
        yield 'none while turning it on' => [true, [], [self::violation('connection_ids', ViolationCode::REQUIRED)]];
        yield 'too many' => [false, $tooMany, [self::violation('connection_ids', ViolationCode::TOO_MANY)]];
        yield 'unknown' => [true, [self::UNKNOWN_ID], [self::violation('connection_ids.0', ViolationCode::UNKNOWN)]];
        yield 'each by its position' => [true, [self::UNKNOWN_ID, null, self::UNKNOWN_ID, ''], [
            self::violation('connection_ids.0', ViolationCode::UNKNOWN),
            self::violation('connection_ids.1', ViolationCode::INVALID_TYPE),
            self::violation('connection_ids.3', ViolationCode::INVALID_FORMAT),
        ]];
    }

    /**
     * Connection ids refused are `invalid`, with every violation, and nothing
     * is asked, written, revoked or reported.
     *
     * @param  bool  $enabled
     * @param  list<mixed>  $ids
     * @param  list<array{setting: string, code: string}>  $violations
     * @return void
     */
    #[DataProvider('provideViolations')]
    public function testIdsRefusedAreInvalid(bool $enabled, array $ids, array $violations): void
    {
        $result = $this->service()->update(self::TENANT, $enabled, $ids, Clients::browser(), $this->actor);

        self::assertTrue($result->isInvalid());
        self::assertSame(FailureReason::SETTINGS_INVALID, $result->reason);
        self::assertSame($violations, $result->jsonSerialize()['violations']);
        $this->assertNothingHappened();
    }

    /**
     * A valid id given alongside refused ones is looked up, and its own
     * position named only when it is unknown; a duplicate is dropped silently.
     *
     * @return void
     */
    public function testValidIdsAmongRefusedOnesAreJudgedToo(): void
    {
        $result = $this->turnOn([$this->completed->id, 7, self::UNKNOWN_ID, $this->completed->id]);

        self::assertSame([
            self::violation('connection_ids.1', ViolationCode::INVALID_TYPE),
            self::violation('connection_ids.2', ViolationCode::UNKNOWN),
        ], $result->jsonSerialize()['violations']);

        $updated = self::summaryOf($this->turnOn([$this->completed->id, $this->completed->id]), EnforcementStatus::UPDATED);

        self::assertSame([$this->completed->id], $updated->connectionIds);
        self::assertSame([$this->completed->id], $this->stored()->connection_ids);
    }

    /**
     * Another tenant's connection, and one of a tenant whose id differs only in
     * case, are answered exactly as an id with no connection.
     *
     * @return void
     */
    public function testAnotherTenantsConnectionIsAnsweredAsAnUnknownOne(): void
    {
        $other   = $this->makeConnection(['tenant_id' => 'tenant-2', 'enabled' => true, 'has_completed_sign_in' => true]);
        $variant = $this->makeConnection(['tenant_id' => 'Tenant-1', 'enabled' => true, 'has_completed_sign_in' => true]);

        $unknown = $this->turnOn([self::UNKNOWN_ID])->jsonSerialize();

        self::assertSame($unknown, $this->turnOn([$other->id])->jsonSerialize());
        self::assertSame($unknown, $this->turnOn([$variant->id])->jsonSerialize());
        self::assertSame($unknown, $this->turnOn([strtoupper($this->completed->id)])->jsonSerialize());
        $this->assertNothingHappened();
    }

    /**
     * Turning it on with no connection given that has completed a sign-in is
     * refused, and nothing is asked, written, revoked or reported.
     *
     * @return void
     */
    public function testTurningItOnNeedsACompletedSignIn(): void
    {
        $result = $this->turnOn([$this->untried->id]);

        self::assertTrue($result->isRefused());
        self::assertSame(FailureReason::COMPLETED_SIGN_IN_REQUIRED, $result->reason);
        $this->assertNothingHappened();
    }

    /**
     * A connection that completed a sign-in but is disabled does not count.
     *
     * @return void
     */
    public function testTurningItOnIsRefusedWhenTheOnlyCompletedConnectionIsDisabled(): void
    {
        $this->completed->forceFill(['enabled' => false])->save();

        $result = $this->turnOn([$this->completed->id, $this->untried->id]);

        self::assertSame(FailureReason::COMPLETED_SIGN_IN_REQUIRED, $result->reason);
        $this->assertNothingHappened();
    }

    /**
     * The freshness contract is asked with `sso.enforcement.update` and the
     * maximum age configured for it.
     *
     * @return void
     */
    public function testFreshnessIsAskedWithItsConfiguredMaximumAge(): void
    {
        Config::set('sso.freshness.max_age_seconds.enforcement_update', 120);

        $this->turnOn([$this->completed->id]);
        $this->service()->update(self::TENANT, false, [], Clients::browser(), $this->actor);

        self::assertSame([[FreshnessOperation::ENFORCEMENT_UPDATE, 120], [FreshnessOperation::ENFORCEMENT_UPDATE, 120]], $this->freshness->asked());
    }

    /**
     * A caller whose authentication is stale is refused, and nothing is
     * written, revoked or reported.
     *
     * @return void
     */
    public function testAStaleCallerWritesAndReportsNothing(): void
    {
        $this->freshness->answer(FreshnessOutcome::STALE);

        $result = $this->turnOn([$this->completed->id]);

        self::assertTrue($result->isRefused());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $result->reason);
        self::assertSame([FreshnessOperation::ENFORCEMENT_UPDATE], $this->freshness->operations());
        self::assertSame(0, TenantEnforcement::query()->count());
        self::assertSame([], $this->revocation->calls());
        $this->assertNoEvents();
    }

    /**
     * While the feature is off every change is refused, with nothing looked up,
     * asked or written; a malformed switch fails closed.
     *
     * @return void
     */
    public function testTheFeatureSwitchedOffRefusesEveryChange(): void
    {
        Config::set('sso.features.enforcement', false);

        $result = $this->turnOn([7]);

        self::assertSame(FailureReason::FEATURE_DISABLED, $result->reason);
        $this->assertNothingHappened();

        Config::set('sso.features.enforcement', 'perhaps');

        $this->expectException(\InvalidArgumentException::class);

        $this->turnOn([$this->completed->id]);
    }

    /**
     * An empty or overlong tenant id is the caller's mistake.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInvalidTenantIsAnInvalidArgument(): void
    {
        foreach (['', str_repeat('t', 256)] as $tenantId) {
            try {
                $this->service()->update($tenantId, false, [], Clients::browser());
                self::fail('The tenant was accepted.');
            } catch (\InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }

        $this->expectException(\InvalidArgumentException::class);

        $this->service()->get('');
    }

    /**
     * `get()` answers the rule as stored: off with nothing for a tenant with
     * none, and the stored ids, version and time otherwise.
     *
     * @return void
     */
    public function testGetAnswersTheStoredRule(): void
    {
        self::assertEquals(new EnforcementSummary(self::TENANT, false, []), $this->service()->get(self::TENANT));

        $updated = self::summaryOf($this->turnOn([$this->completed->id]), EnforcementStatus::UPDATED);

        $this->completed->forceFill(['enabled' => false])->save();

        self::assertEquals($updated, $this->service()->get(self::TENANT));
        self::assertEquals(new EnforcementSummary('Tenant-1', false, []), $this->service()->get('Tenant-1'));
    }

    /**
     * Every read, of the rule and of the connections, is on the write
     * connection.
     *
     * @return void
     */
    public function testReadsTheWriteConnection(): void
    {
        $service = $this->service();
        $ids     = [$this->completed->id];

        DB::connection(StorageConnection::name())->setReadPdo(static function (): never {
            throw new \LogicException('The read connection was used.');
        });

        try {
            $updated   = $service->update(self::TENANT, true, $ids, Clients::browser());
            $unchanged = $service->update(self::TENANT, true, $ids, Clients::browser());
            $refused   = $service->update(self::TENANT, true, [$this->untried->id], Clients::browser());
            $read      = $service->get(self::TENANT);
        } finally {
            DB::connection(StorageConnection::name())->setReadPdo(null);
        }

        self::assertSame(EnforcementStatus::UPDATED, $updated->status);
        self::assertSame(EnforcementStatus::UNCHANGED, $unchanged->status);
        self::assertSame(FailureReason::COMPLETED_SIGN_IN_REQUIRED, $refused->reason);
        self::assertTrue($read->enabled);
    }

    /**
     * A revocation that fails rolls the first change back: no row, no event,
     * and the exception propagates.
     *
     * @return void
     */
    public function testAFailedRevocationRollsTheFirstChangeBack(): void
    {
        $failing = new FailingRevocation;

        $this->app?->instance(SessionRevocation::class, $failing);

        try {
            $this->turnOn([$this->completed->id]);
            self::fail('The change succeeded.');
        } catch (\RuntimeException $exception) {
            self::assertSame(FailingRevocation::MESSAGE, $exception->getMessage());
        }

        self::assertSame(1, $failing->calls());
        self::assertSame(0, TenantEnforcement::query()->count());
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        $this->assertNoEvents();
    }

    /**
     * A revocation that fails rolls a later change back: the rule keeps its
     * switch, its connections and its version, and nothing is reported.
     *
     * @return void
     */
    public function testAFailedRevocationRollsALaterChangeBack(): void
    {
        $before  = self::summaryOf($this->service()->update(self::TENANT, false, [$this->completed->id], Clients::browser()), EnforcementStatus::UPDATED);
        $failing = new FailingRevocation;

        $this->app?->instance(SessionRevocation::class, $failing);
        $this->startRecordingEvents();

        try {
            $this->turnOn([$this->completed->id, $this->untried->id]);
            self::fail('The change succeeded.');
        } catch (\RuntimeException $exception) {
            self::assertSame(FailingRevocation::MESSAGE, $exception->getMessage());
        }

        self::assertSame(1, $failing->calls());
        self::assertEquals($before, $this->service()->get(self::TENANT));
        $this->assertNoEvents();
    }

    /**
     * A connection disabled after the first read is seen by the locked read in
     * the transaction: the change is refused, and the row the change locked
     * stays unconfigured, reading as no rule.
     *
     * @return void
     */
    public function testTheLockedRecheckSeesAConnectionDisabledMeanwhile(): void
    {
        $this->freshness->onCheck = function (): void {
            Connection::query()->whereKey($this->completed->id)->update(['enabled' => false]);
        };

        $result = $this->turnOn([$this->completed->id, $this->untried->id]);

        self::assertSame(FailureReason::COMPLETED_SIGN_IN_REQUIRED, $result->reason);
        $this->assertNoRuleStored();
        self::assertSame([], $this->revocation->calls());
        $this->assertNoEvents();
    }

    /**
     * A connection deleted after the first read is `unknown` under the lock,
     * and an existing rule is left as it was.
     *
     * @return void
     */
    public function testTheLockedRecheckSeesAConnectionDeletedMeanwhile(): void
    {
        $before = self::summaryOf($this->service()->update(self::TENANT, false, [$this->completed->id], Clients::browser()), EnforcementStatus::UPDATED);

        $this->startRecordingEvents();

        $this->freshness->onCheck = function (): void {
            Connection::query()->whereKey($this->untried->id)->delete();
        };

        $result = $this->turnOn([$this->completed->id, $this->untried->id]);

        self::assertSame([self::violation('connection_ids.1', ViolationCode::UNKNOWN)], $result->jsonSerialize()['violations']);
        self::assertEquals($before, $this->service()->get(self::TENANT));
        $this->assertNoEvents();
    }

    /**
     * A change that another made the same meanwhile is unchanged under the
     * lock, and reports nothing.
     *
     * @return void
     */
    public function testTheLockedRecheckSeesTheSameChangeMadeMeanwhile(): void
    {
        $this->freshness->onCheck = function (): void {
            $this->makeEnforcement(['enabled' => true, 'connection_ids' => [$this->completed->id], 'version' => '01jbmeanwhilemeanwhile0000']);
        };

        $result = $this->turnOn([$this->completed->id]);

        self::assertSame('01jbmeanwhilemeanwhile0000', self::summaryOf($result, EnforcementStatus::UNCHANGED)->version);
        self::assertSame(1, TenantEnforcement::query()->count());
        self::assertSame([], $this->revocation->calls());
        $this->assertNoEvents();
    }

    /**
     * A tenant whose only row is the unconfigured guard a redemption or a
     * completion inserted answers as no rule: its first change is made on that
     * row, reports no previous version, and is stored with a new version and
     * the time of the change.
     *
     * @return void
     */
    public function testTheFirstChangeOfAnUnconfiguredRowReportsNoPreviousVersion(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app   = $this->app;
        $guard = DB::connection(StorageConnection::name())->transaction(static fn (): TenantEnforcement => $app->make(EnforcementLock::class)->acquire(self::TENANT));

        $this->clock->advance(60);

        self::assertEquals(new EnforcementSummary(self::TENANT, false, []), $this->service()->get(self::TENANT));

        $summary = self::summaryOf($this->turnOn([$this->completed->id]), EnforcementStatus::UPDATED);
        $stored  = $this->stored();

        self::assertSame($guard->id, $stored->id);
        self::assertTrue($summary->enabled);
        self::assertSame([$this->completed->id], $summary->connectionIds);
        self::assertSame($stored->version, $summary->version);
        self::assertSame(26, strlen((string) $summary->version));
        self::assertSame('2026-11-01T09:31:00+00:00', $summary->changedAt?->toIso8601String());
        self::assertNull($this->changedEvent()->previousVersion);
        self::assertSame($stored->version, $this->changedEvent()->version);
        self::assertSame(1, TenantEnforcement::query()->count());
    }

    /**
     * A change refused once it locked a tenant with no rule leaves its row
     * unconfigured, and the next change, the first real one, still reports no
     * previous version.
     *
     * @return void
     */
    public function testAChangeAfterARefusedFirstChangeReportsNoPreviousVersion(): void
    {
        $this->freshness->onCheck = function (): void {
            Connection::query()->whereKey($this->completed->id)->update(['enabled' => false]);
        };

        self::assertSame(FailureReason::COMPLETED_SIGN_IN_REQUIRED, $this->turnOn([$this->completed->id])->reason);

        $this->assertNoRuleStored();

        $this->freshness->onCheck = null;

        Connection::query()->whereKey($this->completed->id)->update(['enabled' => true]);

        self::summaryOf($this->turnOn([$this->completed->id]), EnforcementStatus::UPDATED);

        self::assertNull($this->changedEvent()->previousVersion);
        self::assertSame(1, TenantEnforcement::query()->count());
    }

    /**
     * A tenant whose id differs only in case keeps a rule of its own.
     *
     * @return void
     */
    public function testATenantWhoseIdDiffersInCaseKeepsItsOwnRule(): void
    {
        $variant = $this->makeConnection(['tenant_id' => 'Tenant-1', 'enabled' => true, 'has_completed_sign_in' => true]);

        $lower = self::summaryOf($this->turnOn([$this->completed->id]), EnforcementStatus::UPDATED);
        $upper = self::summaryOf($this->service()->update('Tenant-1', true, [$variant->id], Clients::browser()), EnforcementStatus::UPDATED);

        self::assertSame(2, TenantEnforcement::query()->count());
        self::assertEquals($lower, $this->service()->get(self::TENANT));
        self::assertEquals($upper, $this->service()->get('Tenant-1'));
        self::assertNull($this->changedEvent(1)->previousVersion);
    }

    /**
     * Turn the tenant's enforcement on, satisfied by the ids given, by the
     * acting identity.
     *
     * @param  list<mixed>  $ids
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementResult
     */
    private function turnOn(array $ids): EnforcementResult
    {
        return $this->service()->update(self::TENANT, true, $ids, Clients::browser(), $this->actor);
    }

    /**
     * Assert nothing was asked, stored, revoked or reported.
     *
     * @return void
     */
    private function assertNothingHappened(): void
    {
        self::assertSame([], $this->freshness->asked());
        self::assertSame(0, TenantEnforcement::query()->count());
        self::assertSame([], $this->revocation->calls());
        $this->assertNoEvents();
    }

    /**
     * Assert the tenant has no rule stored: its only row is the unconfigured
     * one the lock inserted, off, with no connection, no version and no time,
     * which every reader answers as none.
     *
     * @return void
     */
    private function assertNoRuleStored(): void
    {
        $row = TenantEnforcement::query()->sole();

        self::assertSame(self::TENANT, $row->tenant_id);
        self::assertFalse($row->enabled);
        self::assertSame([], $row->connection_ids);
        self::assertNull($row->version);
        self::assertNull($row->changed_at);
        self::assertNull((new EnforcementFinder)->find(self::TENANT));
        self::assertEquals(new EnforcementSummary(self::TENANT, false, []), $this->service()->get(self::TENANT));
    }

    /**
     * Turn the tenant's rule off straight after the next read of it, as a
     * change committed after a caller's transaction took its snapshot would
     * leave it: the first read sees the rule as it was, the locked read as it
     * is.
     *
     * @return void
     */
    private function turnOffAfterTheFirstRead(): void
    {
        $table = (new TenantEnforcement)->getTable();
        $done  = false;

        DB::listen(static function (QueryExecuted $query) use ($table, &$done): void {
            $isRead = str_starts_with(strtolower($query->sql), 'select') && str_contains($query->sql, $table);

            if ($done || !$isRead) {
                return;
            }

            $done = true;

            DB::connection($query->connectionName)->table($table)->update(['enabled' => false]);
        });
    }

    /**
     * The tenant's stored row.
     *
     * @return \SineMacula\Laravel\Sso\Models\TenantEnforcement
     */
    private function stored(): TenantEnforcement
    {
        $stored = (new EnforcementFinder)->find(self::TENANT);

        self::assertNotNull($stored, 'The tenant has no enforcement stored.');

        return $stored;
    }

    /**
     * The changes reported, in order.
     *
     * @return list<\SineMacula\Laravel\Sso\Events\EnforcementChanged>
     */
    private function changedEvents(): array
    {
        return array_values(array_filter($this->recordedEvents(), static fn (object $event): bool => $event instanceof EnforcementChanged));
    }

    /**
     * The change reported at the position given.
     *
     * @param  int  $position
     * @return \SineMacula\Laravel\Sso\Events\EnforcementChanged
     */
    private function changedEvent(int $position = 0): EnforcementChanged
    {
        $events = $this->changedEvents();

        self::assertArrayHasKey($position, $events, 'The change was not reported.');

        return $events[$position];
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

    /**
     * The summary a successful result of the status carries.
     *
     * @param  \SineMacula\Laravel\Sso\Enforcement\EnforcementResult  $result
     * @param  \SineMacula\Laravel\Sso\Enforcement\Enums\EnforcementStatus  $status
     * @return \SineMacula\Laravel\Sso\Enforcement\EnforcementSummary
     */
    private static function summaryOf(EnforcementResult $result, EnforcementStatus $status): EnforcementSummary
    {
        self::assertSame($status, $result->status, (string) json_encode($result));
        self::assertNotNull($result->enforcement);

        return $result->enforcement;
    }

    /**
     * The ids, in id order.
     *
     * @param  list<string>  $ids
     * @return list<string>
     */
    private static function sortedIds(array $ids): array
    {
        sort($ids, SORT_STRING);

        return $ids;
    }

    /**
     * A violation as a result encodes it.
     *
     * @param  string  $setting
     * @param  \SineMacula\Laravel\Sso\Connections\Enums\ViolationCode  $code
     * @return array{setting: string, code: string}
     */
    private static function violation(string $setting, ViolationCode $code): array
    {
        return ['setting' => $setting, 'code' => $code->value];
    }
}
