<?php

declare(strict_types = 1);

namespace Tests\Feature\Domains;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Administration\DomainEvents;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DnsLookup;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Domains\DomainWithdrawal;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Domains\Enums\DomainStatus;
use SineMacula\Laravel\Sso\Events\DomainRemoved;
use SineMacula\Laravel\Sso\Events\DomainVerified;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Models\Domain;
use Tests\Fixtures\Domains\RecordingWithdrawal;

/**
 * Feature tests for verifying and removing a domain (SSO-3.2, SSO-2.12,
 * SSO-11.8, decision D3): a domain is verified only when a TXT record at its
 * record name is exactly its token; a missing or different record and a failed
 * lookup each refuse, a failed lookup never read as either; an expired claim, a
 * stale caller and a rate-limited connection are refused before the lookup; a
 * verified domain is unchanged; a lapsed domain counts from its new time; a
 * domain verified elsewhere, or a claim removed, claimed again or expired,
 * between the lookup and the write is refused, and one verified meanwhile is
 * unchanged; the unique index is the last guard; a removal in any state
 * withdraws linking inside its transaction; and every read is on the write
 * connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainService::class)]
#[CoversClass(DomainEvents::class)]
final class DomainVerificationTest extends DomainServiceTestCase
{
    /** @var string The record name the default claim is looked up at. */
    private const string RECORD = '_sso-verification.example.com';

    /**
     * A record that is exactly the token verifies the domain for the connection
     * from now: the domain is held, the expiry cleared, the check recorded,
     * `sso.domain.verify` asked, and one `DomainVerified` reported without the
     * token.
     *
     * @return void
     */
    public function testVerifiesADomainWhoseRecordIsTheToken(): void
    {
        $claimed = self::summaryOf($this->claimDomain());

        $this->dns->publishes($claimed);
        $this->clock->advance(3600);
        $this->freshness->reset();
        $this->startRecordingEvents();

        $result  = $this->verifyDomain();
        $summary = self::summaryOf($result);

        self::assertSame(DomainStatus::VERIFIED, $result->status);
        self::assertTrue($summary->isVerified());
        self::assertSame('2026-11-01T10:30:00+00:00', $summary->verifiedAt?->toAtomString());
        self::assertSame('2026-11-01T10:30:00+00:00', $summary->lastSuccessfulCheckAt?->toAtomString());
        self::assertNull($summary->pendingExpiresAt);
        self::assertSame('example.com', Domain::query()->findOrFail($claimed->id)->verified_domain);
        self::assertSame(1, Domain::query()->findOrFail($claimed->id)->verification_generation);
        self::assertSame([[FreshnessOperation::DOMAIN_VERIFY, 300]], $this->freshness->asked());
        $this->dns->assertLookedUp(self::RECORD, 1);

        $this->assertEventSequence([DomainVerified::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(DomainVerified::class, $event);
        self::assertSame('2026-11-01T10:30:00+00:00', $event->verifiedAt->toAtomString());
        self::assertSame('42', $event->context->actingIdentityId);
        self::assertStringNotContainsString($claimed->verificationToken(), serialize($event));
    }

    /**
     * One of several records being the token is enough.
     *
     * @return void
     */
    public function testVerifiesWhenOneOfSeveralRecordsIsTheToken(): void
    {
        $claimed = self::summaryOf($this->claimDomain());

        $this->dns->found(self::RECORD, 'v=spf1 -all', $claimed->verificationToken(), 'another-verification=abc');

        self::assertSame(DomainStatus::VERIFIED, $this->verifyDomain()->status);
    }

    /**
     * Rows of `[record]`, each built from the token: a value that carries the
     * token without being exactly it.
     *
     * @return iterable<string, array{\Closure(string): string}>
     */
    public static function provideRecordsThatAreNotTheToken(): iterable
    {
        yield 'with a prefix' => [static fn (string $token): string => 'sso-verification=' . $token];
        yield 'with a suffix' => [static fn (string $token): string => $token . ' '];
        yield 'in capitals' => [static fn (string $token): string => strtoupper($token)];
        yield 'cut short' => [static fn (string $token): string => substr($token, 0, -1)];
        yield 'empty' => [static fn (string $token): string => ''];
    }

    /**
     * A record that is not exactly the token is `domain_record_not_found`, and
     * nothing is written or reported.
     *
     * @param  \Closure(string): string  $record
     * @return void
     */
    #[DataProvider('provideRecordsThatAreNotTheToken')]
    public function testRefusesARecordThatIsNotExactlyTheToken(\Closure $record): void
    {
        $claimed = self::summaryOf($this->claimDomain());

        $this->dns->found(self::RECORD, $record($claimed->verificationToken()));
        $this->startRecordingEvents();

        $result = $this->verifyDomain();

        self::assertSame(FailureReason::DOMAIN_RECORD_NOT_FOUND, $result->reason);
        self::assertSame(DomainState::PENDING, Domain::query()->findOrFail($claimed->id)->state);
        $this->assertNoEvents();
    }

    /**
     * No record at the name is `domain_record_not_found`.
     *
     * @return void
     */
    public function testRefusesAnAbsentRecord(): void
    {
        $this->claimDomain();
        $this->dns->absent(self::RECORD);

        self::assertSame(FailureReason::DOMAIN_RECORD_NOT_FOUND, $this->verifyDomain()->reason);
    }

    /**
     * A lookup that failed is `domain_lookup_failed`: never read as a missing
     * record or as a verification, so the claim stays pending, unchanged, and
     * nothing is reported.
     *
     * @return void
     */
    public function testAFailedLookupIsNeverReadAsAbsentOrAsSuccess(): void
    {
        $claimed = self::summaryOf($this->claimDomain());

        $this->dns->failing(self::RECORD);
        $this->startRecordingEvents();

        $result = $this->verifyDomain();
        $row    = Domain::query()->findOrFail($claimed->id);

        self::assertTrue($result->isRefused());
        self::assertSame(FailureReason::DOMAIN_LOOKUP_FAILED, $result->reason);
        self::assertSame(DomainState::PENDING, $row->state);
        self::assertNull($row->verified_domain);
        self::assertSame('2026-11-08T09:30:00+00:00', $row->pending_expires_at?->toAtomString());
        $this->assertNoEvents();
    }

    /**
     * An expired claim is `domain_claim_expired`, before freshness is asked or
     * anything looked up.
     *
     * @return void
     */
    public function testRefusesAnExpiredClaimBeforeAnyLookup(): void
    {
        $this->claimDomain();
        $this->clock->advance(604800);
        $this->freshness->reset();

        self::assertSame(FailureReason::DOMAIN_CLAIM_EXPIRED, $this->verifyDomain()->reason);
        self::assertSame([], $this->freshness->operations());
        $this->dns->assertNothingLookedUp();
    }

    /**
     * A stale caller is refused before anything is looked up or counted.
     *
     * @return void
     */
    public function testAStaleCallerIsRefusedBeforeAnyLookup(): void
    {
        $this->claimDomain();
        $this->freshness->answer(FreshnessOutcome::STALE);

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $this->verifyDomain()->reason);
        self::assertSame(0, DB::table('sso_rate_limits')->count());
        $this->dns->assertNothingLookedUp();
    }

    /**
     * A verified domain is `unchanged`, once freshness was asked, with nothing
     * looked up, written or reported.
     *
     * @return void
     */
    public function testAVerifiedDomainIsUnchanged(): void
    {
        $claim = $this->makeDomain($this->connection, 'example.com', ['state' => DomainState::VERIFIED, 'verification_generation' => 1]);

        $result = $this->verifyDomain();

        self::assertSame(DomainStatus::UNCHANGED, $result->status);
        self::assertSame(1, Domain::query()->findOrFail($claim->id)->verification_generation);
        self::assertTrue($result->isSucceeded());
        self::assertFalse($result->isChanged());
        self::assertSame($claim->id, $result->domain?->id);
        self::assertSame([FreshnessOperation::DOMAIN_VERIFY], $this->freshness->operations());
        $this->dns->assertNothingLookedUp();
        $this->assertNoEvents();
    }

    /**
     * Each verification takes one of the connection's domain checks; once they
     * are used up it is `rate_limited`, with the seconds to wait, and nothing
     * is looked up.
     *
     * @return void
     */
    public function testVerificationIsRateLimitedPerConnection(): void
    {
        config()->set('sso.rate_limits.domain_check.per_connection', ['max' => 2, 'decay_seconds' => 3600]);

        $this->claimDomain();
        $this->dns->absent(self::RECORD);

        $this->verifyDomain();
        $this->verifyDomain();

        $result = $this->verifyDomain();

        self::assertTrue($result->isRateLimited());
        self::assertSame(FailureReason::RATE_LIMITED, $result->reason);
        self::assertGreaterThanOrEqual(1, $result->retryAfter);
        self::assertLessThanOrEqual(3600, $result->retryAfter);
        $this->dns->assertLookedUp(self::RECORD, 2);
        self::assertSame(DomainStatus::CLAIMED, $this->claimDomain('example.org')->status);
    }

    /**
     * A lapsed domain, which keeps its last successful check for display, is
     * verified again, and counts from its new verification time and its new
     * check, never from its claim or its old check.
     *
     * @return void
     */
    public function testALapsedDomainIsVerifiedAgainFromItsNewTime(): void
    {
        $claim = $this->makeDomain($this->connection, 'example.com', [
            'state'                    => DomainState::LAPSED,
            'pending_expires_at'       => null,
            'last_successful_check_at' => CarbonImmutable::parse('2026-10-29T09:30:00Z'),
            'lapsed_at'                => $this->clock->now()->subDay(),
            'verification_generation'  => 1,
        ]);

        $this->clock->advance(3600);
        $this->dns->found(self::RECORD, $claim->verification_token);

        $summary = self::summaryOf($this->verifyDomain());

        self::assertSame(2, Domain::query()->findOrFail($claim->id)->verification_generation);
        self::assertSame(DomainState::VERIFIED, $summary->state);
        self::assertSame('2026-11-01T10:30:00+00:00', $summary->verifiedAt?->toAtomString());
        self::assertSame('2026-11-01T10:30:00+00:00', $summary->lastSuccessfulCheckAt?->toAtomString());
        self::assertSame('2026-11-01T09:30:00+00:00', $summary->claimedAt->toAtomString());
        self::assertNull($summary->lapsedAt);
    }

    /**
     * A claim that expires while its record is looked up is
     * `domain_claim_expired`, judged again under the lock: it stays pending,
     * holds no domain, and nothing is reported.
     *
     * @return void
     */
    public function testRefusesAClaimThatExpiredDuringTheLookup(): void
    {
        $claimed = self::summaryOf($this->claimDomain());

        $this->dns->answer(self::RECORD, function () use ($claimed): DnsLookup {
            $this->clock->advance(604800);

            return DnsLookup::found([$claimed->verificationToken()]);
        });

        $this->startRecordingEvents();

        $result = $this->verifyDomain();
        $row    = Domain::query()->findOrFail($claimed->id);

        self::assertSame(FailureReason::DOMAIN_CLAIM_EXPIRED, $result->reason);
        self::assertSame(DomainState::PENDING, $row->state);
        self::assertNull($row->verified_domain);
        self::assertNull($row->verified_at);
        $this->dns->assertLookedUp(self::RECORD, 1);
        $this->assertNoEvents();
    }

    /**
     * A claim the same connection verified while its record was looked up is
     * `unchanged`, judged again under the lock: its verification time is kept,
     * and nothing more is reported.
     *
     * @return void
     */
    public function testAClaimVerifiedMeanwhileIsUnchanged(): void
    {
        $claimed = self::summaryOf($this->claimDomain());

        $this->dns->answer(self::RECORD, function () use ($claimed): DnsLookup {
            Domain::query()->findOrFail($claimed->id)->forceFill([
                'state'                    => DomainState::VERIFIED,
                'verified_domain'          => 'example.com',
                'pending_expires_at'       => null,
                'verified_at'              => $this->clock->now(),
                'last_successful_check_at' => $this->clock->now(),
            ])->save();

            $this->clock->advance(60);

            return DnsLookup::found([$claimed->verificationToken()]);
        });

        $this->startRecordingEvents();

        $result = $this->verifyDomain();

        self::assertSame(DomainStatus::UNCHANGED, $result->status);
        self::assertSame('2026-11-01T09:30:00+00:00', self::summaryOf($result)->verifiedAt?->toAtomString());
        self::assertSame('2026-11-01T09:30:00+00:00', Domain::query()->findOrFail($claimed->id)->verified_at?->toAtomString());
        $this->assertNoEvents();
    }

    /**
     * A pending claim verified and then lapsed by a recheck while its record is
     * looked up is `domain_record_not_found`: the newer check found no record,
     * and the older answer never verifies it again.
     *
     * @return void
     */
    public function testRefusesAClaimThatLapsedDuringTheLookup(): void
    {
        $claimed = self::summaryOf($this->claimDomain());

        $this->dns->answer(self::RECORD, function () use ($claimed): DnsLookup {
            $this->lapse($claimed->id, $this->clock->now());

            return DnsLookup::found([$claimed->verificationToken()]);
        });

        $this->startRecordingEvents();

        $result = $this->verifyDomain();
        $stored = Domain::query()->findOrFail($claimed->id);

        self::assertSame(DomainStatus::REFUSED, $result->status);
        self::assertSame(FailureReason::DOMAIN_RECORD_NOT_FOUND, $result->reason);
        self::assertSame(DomainState::LAPSED, $stored->state);
        self::assertNull($stored->verified_domain);
        $this->assertNoEvents();
    }

    /**
     * A lapsed claim verified and lapsed again while its record is looked up is
     * `domain_record_not_found`, judged by its new lapse time; the same lapse
     * it had when read is verified again.
     *
     * @return void
     */
    public function testRefusesAClaimThatLapsedAgainDuringTheLookup(): void
    {
        $claim = $this->makeDomain($this->connection, 'example.com', [
            'state'              => DomainState::LAPSED,
            'pending_expires_at' => null,
            'lapsed_at'          => $this->clock->now()->subDay(),
        ]);

        $this->dns->answer(self::RECORD, function () use ($claim): DnsLookup {
            $this->lapse($claim->id, $this->clock->now());

            return DnsLookup::found([$claim->verification_token]);
        });

        $refused = $this->verifyDomain();

        $this->dns->found(self::RECORD, $claim->verification_token);

        self::assertSame(FailureReason::DOMAIN_RECORD_NOT_FOUND, $refused->reason);
        self::assertSame(DomainStatus::VERIFIED, $this->verifyDomain()->status);
    }

    /**
     * A domain verified for another connection between the lookup and the write
     * is `domain_unavailable`, and the claim stays pending.
     *
     * @return void
     */
    public function testRefusesADomainVerifiedElsewhereMeanwhile(): void
    {
        $claimed = self::summaryOf($this->claimDomain());
        $other   = $this->makeConnection(['tenant_id' => 'tenant-2']);

        $this->dns->answer(self::RECORD, function () use ($claimed, $other): DnsLookup {
            $this->makeDomain($other, 'example.com', ['state' => DomainState::VERIFIED]);

            return DnsLookup::found([$claimed->verificationToken()]);
        });

        $this->startRecordingEvents();

        $result = $this->verifyDomain();

        self::assertSame(FailureReason::DOMAIN_UNAVAILABLE, $result->reason);
        self::assertStringNotContainsString('tenant-2', (string) json_encode($result));
        self::assertSame(DomainState::PENDING, Domain::query()->findOrFail($claimed->id)->state);
        self::assertSame(0, Domain::query()->findOrFail($claimed->id)->verification_generation);
        $this->assertNoEvents();
    }

    /**
     * A claim removed, or given another token, between the lookup and the write
     * is refused: the record proved the token it was matched against, and no
     * other.
     *
     * @return void
     */
    public function testRefusesAClaimRemovedOrChangedMeanwhile(): void
    {
        $claimed = self::summaryOf($this->claimDomain());

        $this->dns->answer(self::RECORD, static function () use ($claimed): DnsLookup {
            Domain::query()->whereKey($claimed->id)->update(['verification_token' => str_repeat('0', 64)]);

            return DnsLookup::found([$claimed->verificationToken()]);
        });

        self::assertSame(FailureReason::DOMAIN_RECORD_NOT_FOUND, $this->verifyDomain()->reason);

        $this->dns->answer(self::RECORD, static function () use ($claimed): DnsLookup {
            Domain::query()->whereKey($claimed->id)->delete();

            return DnsLookup::found([str_repeat('0', 64)]);
        });

        self::assertSame(FailureReason::DOMAIN_NOT_FOUND, $this->verifyDomain()->reason);
    }

    /**
     * The unique index on the verified domain is the last guard: a row that
     * holds the domain verified though no claim of the domain says so still
     * refuses the verification, as `domain_unavailable`, and nothing changes.
     *
     * @return void
     */
    public function testTheUniqueIndexIsTheLastGuard(): void
    {
        $claimed = self::summaryOf($this->claimDomain());
        $other   = $this->makeDomain($this->makeConnection(['tenant_id' => 'tenant-2']), 'example.org', ['state' => DomainState::VERIFIED]);

        Domain::query()->whereKey($other->id)->update(['verified_domain' => 'example.com']);

        $this->dns->publishes($claimed);
        $this->startRecordingEvents();

        $result = $this->verifyDomain();

        self::assertSame(FailureReason::DOMAIN_UNAVAILABLE, $result->reason);
        self::assertSame(DomainState::PENDING, Domain::query()->findOrFail($claimed->id)->state);
        $this->assertNoEvents();
    }

    /**
     * An unknown domain, a name that cannot be one, another tenant's connection
     * and an unknown connection are each refused before anything is asked.
     *
     * @return void
     */
    public function testRefusesWhatIsNotFound(): void
    {
        $this->claimDomain();
        $this->freshness->reset();

        $domains = $this->domains();

        self::assertSame(FailureReason::DOMAIN_NOT_FOUND, $domains->verify(self::TENANT, $this->connection->id, 'example.org')->reason);
        self::assertSame(FailureReason::DOMAIN_NOT_FOUND, $domains->verify(self::TENANT, $this->connection->id, '*.example.com')->reason);
        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $domains->verify('tenant-2', $this->connection->id, 'example.com')->reason);
        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, $domains->remove(self::TENANT, '01jbunknownconnection00000', 'example.com')->reason);
        self::assertSame(FailureReason::DOMAIN_NOT_FOUND, $domains->remove(self::TENANT, $this->connection->id, 'example.org')->reason);
        self::assertSame([], $this->freshness->operations());
    }

    /**
     * Rows of `[state]`: each state a claim can be removed in.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Sso\Domains\Enums\DomainState}>
     */
    public static function provideStates(): iterable
    {
        yield 'pending' => [DomainState::PENDING];
        yield 'verified' => [DomainState::VERIFIED];
        yield 'lapsed' => [DomainState::LAPSED];
    }

    /**
     * A claim is removed in any state, answered as it was, once
     * `sso.domain.remove` was asked; linking by it is withdrawn inside the
     * removal's transaction, before the delete; one `DomainRemoved` reports the
     * state it was in.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\Enums\DomainState  $state
     * @return void
     */
    #[DataProvider('provideStates')]
    public function testRemovesAClaimInAnyState(DomainState $state): void
    {
        $claim      = $this->makeDomain($this->connection, 'example.com', ['state' => $state]);
        $withdrawal = new RecordingWithdrawal;

        $this->app?->instance(DomainWithdrawal::class, $withdrawal);

        $result = $this->domains()->remove(self::TENANT, $this->connection->id, 'Example.COM', $this->actor);

        self::assertSame(DomainStatus::REMOVED, $result->status);
        self::assertSame($state, $result->domain?->state);
        self::assertSame($claim->id, $result->domain->id);
        self::assertFalse(Domain::query()->whereKey($claim->id)->exists());
        self::assertSame([[$this->connection->id, $claim->id, 1, true]], $withdrawal->calls->getArrayCopy());
        self::assertSame([FreshnessOperation::DOMAIN_REMOVE], $this->freshness->operations());

        $this->assertEventSequence([DomainRemoved::class]);

        $event = $this->recordedEvents()[0];

        self::assertInstanceOf(DomainRemoved::class, $event);
        self::assertSame($state, $event->state);
        self::assertSame('example.com', $event->domain);
    }

    /**
     * A stale caller removes nothing.
     *
     * @return void
     */
    public function testAStaleCallerRemovesNothing(): void
    {
        $claim = $this->makeDomain($this->connection);

        $this->freshness->answer(FreshnessOutcome::STALE);

        $result = $this->domains()->remove(self::TENANT, $this->connection->id, 'example.com');

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $result->reason);
        self::assertTrue(Domain::query()->whereKey($claim->id)->exists());
        $this->assertNoEvents();
    }

    /**
     * A verified domain removed from one connection can be claimed and verified
     * for another.
     *
     * @return void
     */
    public function testRemovingAVerifiedDomainFreesIt(): void
    {
        $this->makeDomain($this->connection, 'example.com', ['state' => DomainState::VERIFIED]);

        $other = $this->makeConnection(['tenant_id' => 'tenant-2']);

        self::assertSame(FailureReason::DOMAIN_UNAVAILABLE, $this->claimDomain('example.com', $other)->reason);

        $this->domains()->remove(self::TENANT, $this->connection->id, 'example.com');

        $claimed = self::summaryOf($this->claimDomain('example.com', $other));

        $this->dns->publishes($claimed);

        self::assertSame(DomainStatus::VERIFIED, $this->verifyDomain('example.com', $other)->status);
    }

    /**
     * Every read a verification and a removal make is on the write connection.
     *
     * @return void
     */
    public function testReadsTheWriteConnection(): void
    {
        $claimed = self::summaryOf($this->claimDomain());
        $domains = $this->domains();
        $id      = $this->connection->id;

        $this->dns->publishes($claimed);

        DB::connection(StorageConnection::name())->setReadPdo(static function (): never {
            throw new \LogicException('The read connection was used.');
        });

        try {
            $verified  = $domains->verify(self::TENANT, $id, 'example.com');
            $unchanged = $domains->verify(self::TENANT, $id, 'example.com');
            $removed   = $domains->remove(self::TENANT, $id, 'example.com');
        } finally {
            DB::connection(StorageConnection::name())->setReadPdo(null);
        }

        self::assertSame(DomainStatus::VERIFIED, $verified->status);
        self::assertSame(DomainStatus::UNCHANGED, $unchanged->status);
        self::assertSame(DomainStatus::REMOVED, $removed->status);
    }

    /**
     * Lapse the claim at the moment given, as a recheck that found no record
     * after its grace would.
     *
     * @param  string  $id
     * @param  \Carbon\CarbonImmutable  $at
     * @return void
     */
    private function lapse(string $id, CarbonImmutable $at): void
    {
        Domain::query()->findOrFail($id)->forceFill([
            'state'                => DomainState::LAPSED,
            'verified_domain'      => null,
            'pending_expires_at'   => null,
            'linking_suspended_at' => $at,
            'lapses_at'            => $at,
            'lapsed_at'            => $at,
        ])->save();
    }
}
