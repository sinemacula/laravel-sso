<?php

declare(strict_types = 1);

namespace Tests\Feature\Domains;

use Carbon\CarbonImmutable;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Administration\DomainEvents;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DnsLookup;
use SineMacula\Laravel\Sso\Domains\DomainRechecker;
use SineMacula\Laravel\Sso\Domains\DomainStanding;
use SineMacula\Laravel\Sso\Domains\DomainWithdrawal;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Domains\Enums\DomainStatus;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckFailure;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Domains\RecheckEntry;
use SineMacula\Laravel\Sso\Domains\RecheckReport;
use SineMacula\Laravel\Sso\Events\DomainLapsed;
use SineMacula\Laravel\Sso\Events\DomainRecheckFailed;
use SineMacula\Laravel\Sso\Events\DomainRestored;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use Tests\Fixtures\Domains\RecordingWithdrawal;

/**
 * Feature tests for the scheduled recheck of verified domains (SSO-3.3,
 * SSO-11.12, SSO-10.3 to SSO-10.5): a record that still carries the token moves
 * the check time and keeps the verification time; one absent or changed
 * suspends linking at once, withdrawing what depends on it inside the
 * transaction, and starts a grace period fixed when it began, during which the
 * domain still routes; a record back within it restores the domain; past it the
 * domain lapses without a lookup and is free for another connection; a failed
 * lookup changes nothing but the lease; pending and lapsed claims are left
 * alone; a claim changed or leased by another server is skipped, and so is a
 * lookup that outlasts its lease; a domain verified again counts from its new
 * time; every read is on the write connection; and the claims are read in
 * chunks, in order.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainRechecker::class)]
#[CoversClass(DomainEvents::class)]
#[CoversClass(RecheckEntry::class)]
final class DomainRecheckerTest extends DomainServiceTestCase
{
    /** @var string The record name the default claim is looked up at. */
    private const string RECORD = '_sso-verification.example.com';

    /** @var string The token `makeDomain()` gives a claim. */
    private const string TOKEN = 'abababababababababababababababababababababababababababababababab';

    /** @var int The linking maximum age the predicates are judged with. */
    private const int MAX_AGE = 86400;

    /**
     * A record that still carries the token moves the last successful check to
     * now, keeps the verification time and the claim's other times, releases
     * the lease, and reports nothing.
     *
     * @return void
     */
    public function testAConfirmedCheckMovesTheCheckTimeAndKeepsTheVerificationTime(): void
    {
        $claim = $this->verifiedClaim();

        $this->clock->advance(3600);
        $this->dns->found(self::RECORD, 'v=spf1 -all', self::TOKEN);

        $report = $this->runRecheck();
        $row    = self::reload($claim);
        $entry  = $report->entries[0];

        self::assertCount(1, $report->entries);
        self::assertSame(RecheckOutcome::CONFIRMED, $entry->outcome);
        self::assertSame([$claim->id, $this->connection->id, 'example.com', null], [$entry->domainId, $entry->connectionId, $entry->domain, $entry->lapsesAt]);
        self::assertSame('2026-11-01T10:30:00+00:00', $row->last_successful_check_at?->toAtomString());
        self::assertSame('2026-11-01T09:30:00+00:00', $row->verified_at?->toAtomString());
        self::assertSame(DomainState::VERIFIED, $row->state);
        self::assertSame('example.com', $row->verified_domain);
        self::assertNull($row->linking_suspended_at);
        self::assertNull($row->recheck_leased_until);
        $this->dns->assertLookedUp(self::RECORD, 1);
        $this->assertNoEvents();
    }

    /**
     * Rows of `[answer, failure]`: a record absent, one that is something else,
     * and one that contains the token without being exactly it.
     *
     * @return iterable<string, array{\Closure(\SineMacula\Laravel\Sso\Testing\FakeDnsResolver): void, \SineMacula\Laravel\Sso\Domains\Enums\RecheckFailure}>
     */
    public static function provideRecordsGone(): iterable
    {
        yield 'absent' => [static function (FakeDnsResolver $dns): void {
            $dns->absent(self::RECORD);
        }, RecheckFailure::RECORD_ABSENT];

        yield 'changed' => [static function (FakeDnsResolver $dns): void {
            $dns->found(self::RECORD, 'v=spf1 -all');
        }, RecheckFailure::RECORD_CHANGED];

        yield 'containing the token' => [static function (FakeDnsResolver $dns): void {
            $dns->found(self::RECORD, 'sso-verification=' . self::TOKEN);
        }, RecheckFailure::RECORD_CHANGED];
    }

    /**
     * A record absent or changed suspends linking at once and fixes the lapse
     * at now plus the grace period, while the domain still routes; the
     * withdrawal runs once, inside the transaction, with the claim's row still
     * there; one `DomainRecheckFailed` reports the failure and the lapse time,
     * with no acting identity.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Testing\FakeDnsResolver): void  $answer
     * @param  \SineMacula\Laravel\Sso\Domains\Enums\RecheckFailure  $failure
     * @return void
     */
    #[DataProvider('provideRecordsGone')]
    public function testARecordGoneSuspendsLinkingAtOnce(\Closure $answer, RecheckFailure $failure): void
    {
        $withdrawal = new RecordingWithdrawal;
        $claim      = $this->verifiedClaim();

        $this->app?->instance(DomainWithdrawal::class, $withdrawal);
        $this->clock->advance(3600);
        $answer($this->dns);

        $now = $this->clock->now();

        self::assertTrue(DomainStanding::allowsLinking(self::reload($claim), $now, self::MAX_AGE));

        $report = $this->runRecheck();
        $row    = self::reload($claim);

        self::assertSame(RecheckOutcome::SUSPENDED, $report->entries[0]->outcome);
        self::assertSame('2026-11-04T10:30:00+00:00', $report->entries[0]->lapsesAt?->toAtomString());
        self::assertSame('2026-11-01T10:30:00+00:00', $row->linking_suspended_at?->toAtomString());
        self::assertSame('2026-11-04T10:30:00+00:00', $row->lapses_at?->toAtomString());
        self::assertSame('2026-11-01T09:30:00+00:00', $row->last_successful_check_at?->toAtomString());
        self::assertSame(DomainState::VERIFIED, $row->state);
        self::assertNull($row->recheck_leased_until);
        self::assertFalse(DomainStanding::allowsLinking($row, $now, self::MAX_AGE));
        self::assertTrue(DomainStanding::routes($row, $now));
        self::assertSame([[$this->connection->id, $claim->id, 1, true]], $withdrawal->calls->getArrayCopy());

        $this->assertEventSequence([DomainRecheckFailed::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(DomainRecheckFailed::class, $event);
        self::assertSame($failure, $event->failure);
        self::assertSame($claim->id, $event->domainId);
        self::assertSame('2026-11-04T10:30:00+00:00', $event->lapsesAt?->toAtomString());
        self::assertSame($this->connection->id, $event->context->connectionId);
        self::assertSame(self::TENANT, $event->context->tenantId);
        self::assertNull($event->context->actingIdentityId);
        self::assertStringNotContainsString(self::TOKEN, serialize($event));
    }

    /**
     * A record still gone within the grace period keeps both times, reports
     * again, and withdraws nothing more; the grace period configured since does
     * not move the lapse.
     *
     * @return void
     */
    public function testARecordStillGoneKeepsItsTimesWhateverTheGraceNowIs(): void
    {
        $withdrawal = new RecordingWithdrawal;
        $claim      = $this->verifiedClaim();

        $this->app?->instance(DomainWithdrawal::class, $withdrawal);
        $this->clock->advance(3600);
        $this->dns->absent(self::RECORD);
        $this->runRecheck();

        config()->set('sso.domains.recheck_grace_seconds', 60);

        $this->clock->advance(3600);
        $this->startRecordingEvents();

        $report = $this->runRecheck();
        $row    = self::reload($claim);

        self::assertSame(RecheckOutcome::STILL_FAILING, $report->entries[0]->outcome);
        self::assertSame('2026-11-01T10:30:00+00:00', $row->linking_suspended_at?->toAtomString());
        self::assertSame('2026-11-04T10:30:00+00:00', $row->lapses_at?->toAtomString());
        self::assertSame(DomainState::VERIFIED, $row->state);
        self::assertCount(1, $withdrawal->calls);

        $this->assertEventSequence([DomainRecheckFailed::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(DomainRecheckFailed::class, $event);
        self::assertSame(RecheckFailure::RECORD_ABSENT, $event->failure);
        self::assertSame('2026-11-04T10:30:00+00:00', $event->lapsesAt?->toAtomString());
    }

    /**
     * A record back within the grace period restores the domain: the suspension
     * and the lapse are cleared, the check time moves to now, the verification
     * time is kept, and one `DomainRestored` reports both.
     *
     * @return void
     */
    public function testARecordBackWithinTheGracePeriodRestoresTheDomain(): void
    {
        $claim = $this->verifiedClaim();

        $this->clock->advance(3600);
        $this->dns->absent(self::RECORD);
        $this->runRecheck();

        $this->clock->advance(3600);
        $this->dns->found(self::RECORD, self::TOKEN);
        $this->startRecordingEvents();

        $report = $this->runRecheck();
        $row    = self::reload($claim);

        self::assertSame(RecheckOutcome::RESTORED, $report->entries[0]->outcome);
        self::assertNull($report->entries[0]->lapsesAt);
        self::assertNull($row->linking_suspended_at);
        self::assertNull($row->lapses_at);
        self::assertSame('2026-11-01T11:30:00+00:00', $row->last_successful_check_at?->toAtomString());
        self::assertSame('2026-11-01T09:30:00+00:00', $row->verified_at?->toAtomString());
        self::assertTrue(DomainStanding::allowsLinking($row, $this->clock->now(), self::MAX_AGE));

        $this->assertEventSequence([DomainRestored::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(DomainRestored::class, $event);
        self::assertSame('2026-11-01T09:30:00+00:00', $event->verifiedAt->toAtomString());
        self::assertSame('2026-11-01T11:30:00+00:00', $event->checkedAt->toAtomString());
    }

    /**
     * Past its grace period a domain lapses without a lookup, though its record
     * has come back: what depends on it is withdrawn inside the transaction, it
     * no longer routes, it keeps its last check for display, one `DomainLapsed`
     * reports it, and another tenant can then claim and verify it.
     *
     * @return void
     */
    public function testPastTheGracePeriodADomainLapsesWithoutALookup(): void
    {
        $withdrawal = new RecordingWithdrawal;
        $claim      = $this->verifiedClaim('example.com', [
            'last_successful_check_at' => CarbonImmutable::parse('2026-10-29T09:30:00Z'),
            'linking_suspended_at'     => CarbonImmutable::parse('2026-10-29T10:30:00Z'),
            'lapses_at'                => CarbonImmutable::parse('2026-11-01T10:00:00Z'),
        ]);

        $this->app?->instance(DomainWithdrawal::class, $withdrawal);
        $this->clock->advance(3600);
        $this->dns->found(self::RECORD, self::TOKEN);

        $report = $this->runRecheck();
        $row    = self::reload($claim);

        self::assertSame(RecheckOutcome::LAPSED, $report->entries[0]->outcome);
        $this->dns->assertNothingLookedUp();
        self::assertSame(DomainState::LAPSED, $row->state);
        self::assertSame([null, null, null, null], [$row->verified_domain, $row->verified_at, $row->lapses_at, $row->linking_suspended_at]);
        self::assertSame('2026-11-01T10:30:00+00:00', $row->lapsed_at?->toAtomString());
        self::assertSame('2026-10-29T09:30:00+00:00', $row->last_successful_check_at?->toAtomString());
        self::assertNull($row->recheck_leased_until);
        self::assertFalse(DomainStanding::routes($row, $this->clock->now()));
        self::assertSame([[$this->connection->id, $claim->id, 1, true]], $withdrawal->calls->getArrayCopy());
        $this->assertEventSequence([DomainLapsed::class]);

        $other   = $this->makeConnection(['tenant_id' => 'tenant-2']);
        $claimed = self::summaryOf($this->claimDomain('example.com', $other));

        $this->dns->publishes($claimed);

        self::assertSame(DomainStatus::VERIFIED, $this->verifyDomain('example.com', $other)->status);
    }

    /**
     * With no grace period, one run suspends the domain and lapses it, each
     * withdrawal before its own write, reporting the failure and then the
     * lapse.
     *
     * @return void
     */
    public function testWithNoGracePeriodOneRunSuspendsAndLapses(): void
    {
        config()->set('sso.domains.recheck_grace_seconds', 0);

        $seen  = $this->bindWithdrawalProbe();
        $claim = $this->verifiedClaim();

        $this->clock->advance(3600);
        $this->dns->absent(self::RECORD);

        $report = $this->runRecheck();
        $row    = self::reload($claim);

        self::assertSame(RecheckOutcome::LAPSED, $report->entries[0]->outcome);
        self::assertSame(DomainState::LAPSED, $row->state);
        self::assertNull($row->verified_domain);
        self::assertSame([['verified', null], ['verified', '2026-11-01T10:30:00+00:00']], $seen->getArrayCopy());

        $this->assertEventSequence([DomainRecheckFailed::class, DomainLapsed::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(DomainRecheckFailed::class, $event);
        self::assertSame(RecheckFailure::RECORD_ABSENT, $event->failure);
        self::assertSame('2026-11-01T10:30:00+00:00', $event->lapsesAt?->toAtomString());
    }

    /**
     * A failed lookup changes no column but the lease (and the update time), is
     * never read as a record gone or as a success, and is reported with the
     * lapse time as it stands; linking by the domain still stops once its last
     * successful check is a day old.
     *
     * @return void
     */
    public function testAFailedLookupChangesNothingButTheLease(): void
    {
        $plain     = $this->verifiedClaim();
        $suspended = $this->verifiedClaim('example.org', [
            'linking_suspended_at' => CarbonImmutable::parse('2026-11-01T08:30:00Z'),
            'lapses_at'            => CarbonImmutable::parse('2026-11-03T08:30:00Z'),
        ]);

        $this->clock->advance(3600);
        $this->dns->failing(self::RECORD)->failing('_sso-verification.example.org');

        $before = [Arr::except(self::reload($plain)->getAttributes(), 'updated_at'), Arr::except(self::reload($suspended)->getAttributes(), 'updated_at')];
        $report = $this->runRecheck();
        $after  = [Arr::except(self::reload($plain)->getAttributes(), 'updated_at'), Arr::except(self::reload($suspended)->getAttributes(), 'updated_at')];

        self::assertSame(2, $report->count(RecheckOutcome::LOOKUP_FAILED));
        self::assertTrue($report->hasLookupFailures());
        self::assertSame($before, $after);
        self::assertNull($after[0]['recheck_leased_until']);

        $this->assertEventSequence([DomainRecheckFailed::class, DomainRecheckFailed::class]);

        $lapses = [];

        foreach ($this->recordedEvents() as $event) {
            self::assertInstanceOf(DomainRecheckFailed::class, $event);
            self::assertSame(RecheckFailure::LOOKUP_FAILED, $event->failure);

            $lapses[$event->domain] = $event->lapsesAt?->toAtomString();
        }

        ksort($lapses);

        self::assertSame(['example.com' => null, 'example.org' => '2026-11-03T08:30:00+00:00'], $lapses);

        $later = $this->clock->now()->addSeconds(self::MAX_AGE);

        self::assertFalse(DomainStanding::allowsLinking(self::reload($plain), $later, self::MAX_AGE));
        self::assertTrue(DomainStanding::routes(self::reload($plain), $later));
    }

    /**
     * Pending and lapsed claims are never rechecked.
     *
     * @return void
     */
    public function testPendingAndLapsedClaimsAreNotRechecked(): void
    {
        $this->makeDomain($this->connection, 'pending.example.com');
        $this->makeDomain($this->connection, 'lapsed.example.com', [
            'state'              => DomainState::LAPSED,
            'pending_expires_at' => null,
            'lapsed_at'          => $this->clock->now()->subDay(),
        ]);

        $this->clock->advance(3600);

        self::assertSame([], $this->runRecheck()->entries);
        $this->dns->assertNothingLookedUp();
        $this->assertNoEvents();
    }

    /**
     * A claim removed, replaced by a new verified claim, given another token,
     * or no longer verified between the lookup and the transaction is skipped,
     * with nothing written or reported.
     *
     * @return void
     */
    public function testAClaimChangedBetweenTheLookupAndTheWriteIsSkipped(): void
    {
        $removed   = $this->verifiedClaim('removed.example.com');
        $replaced  = $this->verifiedClaim('replaced.example.com');
        $retokened = $this->verifiedClaim('retokened.example.com');
        $demoted   = $this->verifiedClaim('demoted.example.com');

        $this->clock->advance(3600);

        $this->dns->answer('_sso-verification.removed.example.com', static function () use ($removed): DnsLookup {
            Domain::query()->whereKey($removed->id)->delete();

            return DnsLookup::absent();
        });

        $this->dns->answer('_sso-verification.replaced.example.com', function () use ($replaced): DnsLookup {
            Domain::query()->whereKey($replaced->id)->delete();

            $this->verifiedClaim('replaced.example.com', ['verification_token' => str_repeat('cd', 32)]);

            return DnsLookup::absent();
        });

        $this->dns->answer('_sso-verification.retokened.example.com', static function () use ($retokened): DnsLookup {
            Domain::query()->whereKey($retokened->id)->update(['verification_token' => str_repeat('ef', 32)]);

            return DnsLookup::absent();
        });

        $this->dns->answer('_sso-verification.demoted.example.com', static function () use ($demoted): DnsLookup {
            Domain::query()->whereKey($demoted->id)->update(['state' => DomainState::LAPSED->value, 'verified_domain' => null]);

            return DnsLookup::absent();
        });

        $report = $this->runRecheck();

        self::assertSame(4, $report->count(RecheckOutcome::SKIPPED));
        self::assertCount(4, $report->entries);
        self::assertFalse(Domain::query()->whereKey($removed->id)->exists());
        self::assertSame(0, Domain::query()->whereNotNull('linking_suspended_at')->count());
        self::assertSame(DomainState::LAPSED, self::reload($demoted)->state);
        $this->assertNoEvents();
    }

    /**
     * A claim another server holds the lease of is skipped, with no lookup,
     * until the lease expires; then it is taken over.
     *
     * @return void
     */
    public function testALeaseIsHonoredUntilItExpires(): void
    {
        $claim = $this->verifiedClaim();

        $this->clock->advance(3600);
        $this->dns->found(self::RECORD, self::TOKEN);

        $until = $this->clock->now()->addSeconds(60);

        Domain::query()->whereKey($claim->id)->update(['recheck_leased_until' => UtcDateTime::format(new Domain, $until)]);

        $held = $this->runRecheck();

        self::assertSame(RecheckOutcome::SKIPPED, $held->entries[0]->outcome);
        self::assertNull($held->entries[0]->lapsesAt);
        self::assertSame($until->toAtomString(), self::reload($claim)->recheck_leased_until?->toAtomString());
        $this->dns->assertNothingLookedUp();
        $this->assertNoEvents();

        $this->clock->advance(60);

        $taken = $this->runRecheck();
        $row   = self::reload($claim);

        self::assertSame(RecheckOutcome::CONFIRMED, $taken->entries[0]->outcome);
        self::assertNull($row->recheck_leased_until);
        self::assertSame('2026-11-01T10:31:00+00:00', $row->last_successful_check_at?->toAtomString());
    }

    /**
     * A lookup that outlasts its lease, while another server takes the claim
     * over and suspends it on a newer answer, writes nothing: its older answer
     * that the record is there never lifts the suspension.
     *
     * @return void
     */
    public function testALookupThatOutlastsItsLeaseNeverLiftsANewerSuspension(): void
    {
        $claim = $this->verifiedClaim();

        $this->clock->advance(3600);

        $this->dns->answer(self::RECORD, function () use ($claim): DnsLookup {

            $this->clock->advance(DomainRechecker::LEASE_SECONDS + 1);
            $this->dns->absent(self::RECORD);

            /** @var \Illuminate\Foundation\Application $app */
            $app = $this->app;

            self::assertSame(RecheckOutcome::SUSPENDED, $app->make(DomainRechecker::class)->recheck(self::reload($claim))->outcome);

            return DnsLookup::found([self::TOKEN]);
        });

        $report = $this->runRecheck();
        $row    = self::reload($claim);

        self::assertSame(RecheckOutcome::SKIPPED, $report->entries[0]->outcome);
        self::assertSame('2026-11-01T10:35:01+00:00', $row->linking_suspended_at?->toAtomString());
        self::assertNotNull($row->lapses_at);
        self::assertSame('2026-11-01T09:30:00+00:00', $row->last_successful_check_at?->toAtomString());
        $this->assertEventSequence([DomainRecheckFailed::class]);
    }

    /**
     * A lookup that outlasts its lease writes nothing, even when no other
     * server took the claim over: the next run checks it again.
     *
     * @return void
     */
    public function testALookupThatOutlastsItsLeaseIsSkipped(): void
    {
        $claim = $this->verifiedClaim();

        $this->clock->advance(3600);

        $this->dns->answer(self::RECORD, function (): DnsLookup {
            $this->clock->advance(DomainRechecker::LEASE_SECONDS);

            return DnsLookup::absent();
        });

        $report = $this->runRecheck();
        $row    = self::reload($claim);

        self::assertSame(RecheckOutcome::SKIPPED, $report->entries[0]->outcome);
        self::assertNull($row->linking_suspended_at);
        self::assertSame('2026-11-01T10:35:00+00:00', $row->recheck_leased_until?->toAtomString());
        $this->assertNoEvents();
    }

    /**
     * A claim whose lease another server holds by the time the lookup is
     * written, though this check's lease has not run out, is skipped: only the
     * exact lease this check took lets it write.
     *
     * @return void
     */
    public function testAClaimLeasedByAnotherServerMeanwhileIsSkipped(): void
    {
        $claim = $this->verifiedClaim();

        $this->clock->advance(3600);

        $other = $this->clock->now()->addSeconds(DomainRechecker::LEASE_SECONDS + 60);

        $this->dns->answer(self::RECORD, static function () use ($claim, $other): DnsLookup {
            Domain::query()->whereKey($claim->id)->update(['recheck_leased_until' => UtcDateTime::format(new Domain, $other)]);

            return DnsLookup::absent();
        });

        $report = $this->runRecheck();
        $row    = self::reload($claim);

        self::assertSame(RecheckOutcome::SKIPPED, $report->entries[0]->outcome);
        self::assertNull($row->linking_suspended_at);
        self::assertSame($other->toAtomString(), $row->recheck_leased_until?->toAtomString());
        $this->assertNoEvents();
    }

    /**
     * A lapsed domain verified again counts from its new verification time and
     * its new check, and linking by it follows them.
     *
     * @return void
     */
    public function testALapsedDomainVerifiedAgainCountsFromItsNewTime(): void
    {
        $claim = $this->verifiedClaim('example.com', [
            'linking_suspended_at' => CarbonImmutable::parse('2026-10-29T09:30:00Z'),
            'lapses_at'            => CarbonImmutable::parse('2026-11-01T09:00:00Z'),
        ]);

        $this->clock->advance(3600);

        self::assertSame(RecheckOutcome::LAPSED, $this->runRecheck()->entries[0]->outcome);

        $this->clock->advance(3600);
        $this->dns->found(self::RECORD, self::TOKEN);

        self::assertSame(DomainStatus::VERIFIED, $this->verifyDomain()->status);

        $verified = self::reload($claim);
        $now      = $this->clock->now();

        self::assertSame('2026-11-01T11:30:00+00:00', $verified->verified_at?->toAtomString());
        self::assertSame('2026-11-01T11:30:00+00:00', $verified->last_successful_check_at?->toAtomString());
        self::assertTrue(DomainStanding::allowsLinking($verified, $now, self::MAX_AGE));
        self::assertFalse(DomainStanding::allowsLinking($verified, $now->addSeconds(self::MAX_AGE + 1), self::MAX_AGE));

        $this->clock->advance(7200);

        self::assertSame(RecheckOutcome::CONFIRMED, $this->runRecheck()->entries[0]->outcome);

        $checked = self::reload($claim);

        self::assertSame('2026-11-01T11:30:00+00:00', $checked->verified_at?->toAtomString());
        self::assertSame('2026-11-01T13:30:00+00:00', $checked->last_successful_check_at?->toAtomString());
        self::assertTrue(DomainStanding::allowsLinking($checked, $now->addSeconds(self::MAX_AGE + 1), self::MAX_AGE));
    }

    /**
     * Every read a run makes is on the write connection: the selection, the
     * leases, and the locked reads of a confirmation, a suspension and a lapse.
     *
     * @return void
     */
    public function testReadsTheWriteConnection(): void
    {
        $this->verifiedClaim('confirmed.example.com');
        $this->verifiedClaim('absent.example.com');
        $this->verifiedClaim('lapsing.example.com', [
            'linking_suspended_at' => CarbonImmutable::parse('2026-10-29T09:30:00Z'),
            'lapses_at'            => CarbonImmutable::parse('2026-11-01T09:00:00Z'),
        ]);

        $this->clock->advance(3600);
        $this->dns->found('_sso-verification.confirmed.example.com', self::TOKEN)->absent('_sso-verification.absent.example.com');

        DB::connection(StorageConnection::name())->setReadPdo(static function (): never {
            throw new \LogicException('The read connection was used.');
        });

        try {
            $report = $this->runRecheck();
        } finally {
            DB::connection(StorageConnection::name())->setReadPdo(null);
        }

        self::assertSame(1, $report->count(RecheckOutcome::CONFIRMED));
        self::assertSame(1, $report->count(RecheckOutcome::SUSPENDED));
        self::assertSame(1, $report->count(RecheckOutcome::LAPSED));
    }

    /**
     * More claims than one chunk holds are each checked once, in order of their
     * last successful check and then id, across the chunk boundary, by two
     * bounded reads.
     *
     * @return void
     */
    public function testChecksMoreThanAChunkInOrder(): void
    {
        $base = CarbonImmutable::parse('2026-10-31T09:30:00Z');

        for ($index = 0; $index < 150; $index++) {
            $this->verifiedClaim("d{$index}.example.com", ['last_successful_check_at' => $base->subMinutes(intdiv($index, 7))]);
            $this->dns->found("_sso-verification.d{$index}.example.com", self::TOKEN);
        }

        $expected = Domain::query()->orderBy('last_successful_check_at')->orderBy('id')->pluck('id')->all();
        $chunks   = 0;

        DB::connection(StorageConnection::name())->listen(static function (QueryExecuted $query) use (&$chunks): void {
            if (!str_contains(strtolower($query->sql), 'limit 100')) {
                return;
            }

            $chunks++;
        });

        $this->clock->advance(3600);

        $report = $this->runRecheck();

        self::assertSame($expected, array_map(static fn (RecheckEntry $entry): string => $entry->domainId, $report->entries));
        self::assertSame(150, $report->count(RecheckOutcome::CONFIRMED));
        self::assertSame(2, $chunks);
    }

    /**
     * Run the recheck as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Domains\RecheckReport
     */
    private function runRecheck(): RecheckReport
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(DomainRechecker::class)->recheckAll();
    }

    /**
     * Make the tenant's connection's claim of the domain, verified and checked
     * at the claim's time unless the attributes say otherwise.
     *
     * @param  string  $domain
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Domain
     */
    private function verifiedClaim(string $domain = 'example.com', array $attributes = []): Domain
    {
        return $this->makeDomain($this->connection, $domain, ['state' => DomainState::VERIFIED] + $attributes);
    }

    /**
     * Bind a withdrawal that records, at each call, the claim's stored state
     * and suspension time, so a test proves it ran before the write.
     *
     * @return \ArrayObject<int, array{string, ?string}>
     */
    private function bindWithdrawalProbe(): \ArrayObject
    {
        /** @var \ArrayObject<int, array{string, ?string}> $seen */
        $seen = new \ArrayObject;

        $this->app?->instance(DomainWithdrawal::class, new readonly class ($seen) extends DomainWithdrawal {
            /**
             * Constructor.
             *
             * @param  \ArrayObject<int, array{string, ?string}>  $seen
             */
            public function __construct(

                /** What each call saw. */
                private \ArrayObject $seen,
            ) {}

            /**
             * Record the claim as it is stored.
             *
             * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
             * @param  \SineMacula\Laravel\Sso\Models\Domain  $domain
             * @return void
             */
            #[\Override]
            public function linkingWithdrawn(Connection $connection, Domain $domain): void
            {
                $row = Domain::query()->useWritePdo()->whereKey($domain->id)->firstOrFail();

                $this->seen->append([$row->state->value, $row->linking_suspended_at?->toAtomString()]);
            }
        });

        return $seen;
    }

    /**
     * The claim as it is now stored.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Domain  $claim
     * @return \SineMacula\Laravel\Sso\Models\Domain
     */
    private static function reload(Domain $claim): Domain
    {
        return Domain::query()->findOrFail($claim->id);
    }
}
