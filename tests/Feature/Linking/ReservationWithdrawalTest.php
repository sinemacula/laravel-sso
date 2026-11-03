<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\InFlightVoider;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\DomainRechecker;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Domains\DomainStanding;
use SineMacula\Laravel\Sso\Domains\DomainWithdrawal;
use SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Links\ReservationWithdrawal;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RecordsLockOrder;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Feature tests for everything that withdraws a link reservation (SSO-3.3,
 * SSO-2.13, SSO-8.8), through each change's public path: a domain removed, its
 * record gone or changed, at once and without the grace period, and its lapse;
 * a connection disabled or deleted; a trust change; and what each statement of
 * the withdrawal itself touches, counts and raises. A failed lookup withdraws
 * nothing, and a domain restored brings nothing back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReservationWithdrawal::class)]
#[CoversClass(DomainWithdrawal::class)]
#[CoversClass(InFlightVoider::class)]
#[CoversClass(ConnectionLifecycle::class)]
#[CoversClass(DomainRechecker::class)]
final class ReservationWithdrawalTest extends LinkingTestCase
{
    use RecordsLockOrder;

    /** @var string What the recheck looks the claim's record up at. */
    private const string RECORD = '_sso-verification.example.com';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeDnsResolver The resolver the rechecker reads. */
    private FakeDnsResolver $dns;

    /**
     * Bind fresh authentication and the resolver.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->dns = new FakeDnsResolver;

        $this->app?->instance(Freshness::class, FakeFreshness::fresh());
        $this->app?->instance(DnsResolver::class, $this->dns);
    }

    /**
     * A domain removed takes its reservation with it, raising the links
     * version, and the code is then `reservation_invalid`, with no link.
     *
     * @return void
     */
    public function testRemovingTheDomainDeletesTheReservation(): void
    {
        [$start, $completion] = $this->reserved();

        self::assertTrue(app(DomainService::class)->remove('tenant-1', $this->connection->id, 'example.com')->isChanged());
        self::assertSame(0, Link::query()->count());
        self::assertSame(2, $this->linksVersion());
        self::assertSame(FailureReason::RESERVATION_INVALID, $this->admit($completion, $start)->reason);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * Rows of `[what the record answers, the outcome]`: a record gone or
     * changed suspends linking at once, without the grace period.
     *
     * @return iterable<string, array{0: list<string>, 1: \SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome}>
     */
    public static function provideGoneRecords(): iterable
    {
        yield 'absent' => [[], RecheckOutcome::SUSPENDED];
        yield 'changed' => [['something-else'], RecheckOutcome::SUSPENDED];
    }

    /**
     * A recheck that finds the record gone or changed withdraws the reservation
     * at once, while discovery keeps routing the domain.
     *
     * @param  list<string>  $records
     * @param  \SineMacula\Laravel\Sso\Domains\Enums\RecheckOutcome  $outcome
     * @return void
     */
    #[DataProvider('provideGoneRecords')]
    public function testARecordGoneWithdrawsAtOnce(array $records, RecheckOutcome $outcome): void
    {
        [$start, $completion] = $this->reserved();

        $records === [] ? $this->dns->absent(self::RECORD) : $this->dns->found(self::RECORD, ...$records);

        $entry = app(DomainRechecker::class)->recheck($this->claim());

        self::assertSame($outcome, $entry->outcome);
        self::assertSame(0, Link::query()->count());
        self::assertSame(2, $this->linksVersion());
        self::assertTrue(DomainStanding::routes($this->claim(), $this->clock->now()));
        self::assertFalse(DomainStanding::allowsLinking($this->claim(), $this->clock->now(), 86400));
        self::assertSame(FailureReason::RESERVATION_INVALID, $this->admit($completion, $start)->reason);
    }

    /**
     * A failed lookup says nothing about the record, so it withdraws nothing,
     * and the code still redeems.
     *
     * @return void
     */
    public function testAFailedLookupWithdrawsNothing(): void
    {
        [$start, $completion] = $this->reserved();

        $this->dns->failing(self::RECORD);

        self::assertSame(RecheckOutcome::LOOKUP_FAILED, app(DomainRechecker::class)->recheck($this->claim())->outcome);
        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);
        self::assertTrue($this->admit($completion, $start)->isRedeemed());
    }

    /**
     * A lapse at the end of the grace period withdraws the reservation, even
     * with no lookup.
     *
     * @return void
     */
    public function testALapseDeletesTheReservation(): void
    {
        $this->domain->forceFill(['lapses_at' => $this->clock->now()->addSeconds(30)])->save();

        [$start, $completion] = $this->reserved();

        $this->clock->advance(30);

        self::assertSame(RecheckOutcome::LAPSED, app(DomainRechecker::class)->recheck($this->claim())->outcome);
        self::assertSame(0, Link::query()->count());
        self::assertSame(FailureReason::RESERVATION_INVALID, $this->admit($completion, $start)->reason);
    }

    /**
     * A domain restored within the grace period brings no reservation back, and
     * its code stays dead.
     *
     * @return void
     */
    public function testARestoredDomainBringsNothingBack(): void
    {
        [$start, $completion] = $this->reserved();

        $this->dns->absent(self::RECORD);
        app(DomainRechecker::class)->recheck($this->claim());

        $this->dns->found(self::RECORD, $this->claim()->verification_token);

        self::assertSame(RecheckOutcome::RESTORED, app(DomainRechecker::class)->recheck($this->claim())->outcome);
        self::assertSame(0, Link::query()->count());
        self::assertSame(FailureReason::RESERVATION_INVALID, $this->admit($completion, $start)->reason);
    }

    /**
     * A connection disabled voids the code and deletes the reservation, so the
     * code is `handoff_unknown`.
     *
     * @return void
     */
    public function testDisablingTheConnectionDeletesTheReservation(): void
    {
        [$start, $completion] = $this->reserved();

        self::assertTrue(app(ConnectionLifecycle::class)->disable('tenant-1', $this->connection->id)->isChanged());
        self::assertSame(0, Link::query()->count());
        self::assertSame(FailureReason::HANDOFF_UNKNOWN, $this->admit($completion, $start)->reason);
    }

    /**
     * A connection deleted takes everything with it.
     *
     * @return void
     */
    public function testDeletingTheConnectionDeletesTheReservation(): void
    {
        [$start, $completion] = $this->reserved();

        self::assertTrue(app(ConnectionLifecycle::class)->delete('tenant-1', $this->connection->id)->isChanged());
        self::assertSame(0, Link::query()->count());
        self::assertSame(FailureReason::HANDOFF_UNKNOWN, $this->admit($completion, $start)->reason);
    }

    /**
     * A trust change voids the code, raises the trust version and deletes the
     * reservation, in its transaction.
     *
     * @return void
     */
    public function testATrustChangeDeletesTheReservation(): void
    {
        [$start, $completion] = $this->reserved();

        DB::connection(StorageConnection::name())->transaction(function (): void {

            /** @var \SineMacula\Laravel\Sso\Models\Connection $locked */
            $locked = Connection::query()->useWritePdo()->lockForUpdate()->whereKey($this->connection->id)->first();

            app(InFlightVoider::class)->voidFor($locked);
        });

        self::assertSame(0, Link::query()->count());
        self::assertSame(1, Connection::query()->whereKey($this->connection->id)->sole()->trust_version);
        self::assertSame(FailureReason::HANDOFF_UNKNOWN, $this->admit($completion, $start)->reason);
    }

    /**
     * Of a connection, every reservation goes, whatever its domain and however
     * expired, and is counted; an active or suspended link and another
     * connection's reservation stay; the links version rises once.
     *
     * @return void
     */
    public function testOfConnectionDeletesItsReservationsAlone(): void
    {
        $other = $this->makeConnection(['protocol' => VerifyingDriver::NAME]);

        $this->row($this->connection, 'a', LinkState::RESERVED, 60);
        $this->row($this->connection, 'b', LinkState::RESERVED, -60);
        $this->row($this->connection, 'c', LinkState::ACTIVE);
        $this->row($this->connection, 'd', LinkState::SUSPENDED);

        $kept = $this->row($other, 'e', LinkState::RESERVED, 60);

        self::assertSame(2, ReservationWithdrawal::ofConnection($this->connection));
        self::assertSame(['active', 'suspended'], $this->statesIn($this->connection));
        self::assertSame(LinkState::RESERVED, Link::query()->whereKey($kept->id)->sole()->state);
        self::assertSame(1, $this->linksVersion());
        self::assertSame(0, Connection::query()->whereKey($other->id)->sole()->links_version);
    }

    /**
     * With nothing to delete, none is counted and the links version stays.
     *
     * @return void
     */
    public function testWithNothingToDeleteTheVersionStays(): void
    {
        $this->row($this->connection, 'a', LinkState::ACTIVE);

        self::assertSame(0, ReservationWithdrawal::ofConnection($this->connection));
        self::assertSame(0, ReservationWithdrawal::ofDomain($this->connection, $this->domain));
        self::assertSame(0, ReservationWithdrawal::ofRows($this->connection, Link::query()->get()->all()));
        self::assertSame(0, $this->linksVersion());
        self::assertSame(1, Link::query()->count());
    }

    /**
     * Of a domain, only the reservations bound to it go, and they are counted;
     * one of another domain and an active link stay.
     *
     * @return void
     */
    public function testOfDomainDeletesItsReservationsAlone(): void
    {
        $this->row($this->connection, 'a', LinkState::RESERVED, 60, $this->domain->id);
        $this->row($this->connection, 'b', LinkState::RESERVED, 60, $this->domain->id);

        $kept = $this->row($this->connection, 'c', LinkState::RESERVED, 60, 'another-domain');

        $this->row($this->connection, 'd', LinkState::ACTIVE);

        self::assertSame(2, ReservationWithdrawal::ofDomain($this->connection, $this->domain));
        self::assertSame(LinkState::RESERVED, Link::query()->whereKey($kept->id)->sole()->state);
        self::assertSame(2, Link::query()->count());
        self::assertSame(1, $this->linksVersion());
    }

    /**
     * Of the rows given, only those reserved go, and they are counted; the
     * links version rises once.
     *
     * @return void
     */
    public function testOfRowsDeletesOnlyTheReserved(): void
    {
        $rows = [
            $this->row($this->connection, 'a', LinkState::RESERVED, 60),
            $this->row($this->connection, 'b', LinkState::RESERVED, 60),
            $this->row($this->connection, 'c', LinkState::ACTIVE),
            $this->row($this->connection, 'd', LinkState::SUSPENDED),
        ];

        self::assertSame(2, ReservationWithdrawal::ofRows($this->connection, $rows));
        self::assertSame(['active', 'suspended'], $this->statesIn($this->connection));
        self::assertSame(1, $this->linksVersion());
    }

    /**
     * Of the rows named, only those still reserved and expired by the cutoff
     * go, and they are counted; a row of another connection, past the cutoff,
     * of another state or not named stays; the links version rises once.
     *
     * @return void
     */
    public function testExpiredDeletesOnlyTheExpiredReservationsNamed(): void
    {
        $other = $this->makeConnection(['protocol' => VerifyingDriver::NAME]);
        $now   = $this->clock->now();
        $at    = UtcDateTime::format(new Link, $now);

        $gone    = $this->row($this->connection, 'a', LinkState::RESERVED, -60);
        $edge    = $this->row($this->connection, 'b', LinkState::RESERVED, 0);
        $live    = $this->row($this->connection, 'c', LinkState::RESERVED, 1);
        $active  = $this->row($this->connection, 'd', LinkState::ACTIVE);
        $foreign = $this->row($other, 'e', LinkState::RESERVED, -60);
        $unnamed = $this->row($this->connection, 'f', LinkState::RESERVED, -60);

        $named = [$gone->id, $edge->id, $live->id, $active->id, $foreign->id];

        self::assertSame(2, ReservationWithdrawal::expired($this->connection->id, $named, $at));

        self::assertEqualsCanonicalizing([$live->id, $active->id, $foreign->id, $unnamed->id], Link::query()->pluck('id')->all());
        self::assertSame(1, $this->linksVersion());
        self::assertSame(0, Connection::query()->whereKey($other->id)->sole()->links_version);
    }

    /**
     * Nothing left to delete raises nothing, and it locks the connection first,
     * in a transaction of its own.
     *
     * @return void
     */
    public function testExpiredWithNothingToDeleteLocksTheConnectionAndRaisesNothing(): void
    {
        $statements = [];

        $this->recordLockOrder();

        DB::connection()->listen(static function ($query) use (&$statements): void {
            $statements[] = strtolower($query->sql);
        });

        self::assertSame(0, ReservationWithdrawal::expired($this->connection->id, ['0000000000000000000000000a'], '2026-11-01 12:00:00'));
        self::assertCount(2, $statements);
        self::assertStringContainsString('for update', $statements[0]);
        self::assertStringContainsString('connections', $statements[0]);
        self::assertStringStartsWith('delete', $statements[1]);
        self::assertSame(0, $this->linksVersion());
    }

    /**
     * Complete an eligible flow, holding its reservation.
     *
     * @return array{0: \SineMacula\Laravel\Sso\Flows\StartResult, 1: \SineMacula\Laravel\Sso\Completion\CompletionResult}
     */
    private function reserved(): array
    {
        $start      = $this->start();
        $completion = $this->complete();

        self::assertTrue($completion->isCompleted());
        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);
        self::assertSame(1, $this->linksVersion());

        return [$start, $completion];
    }

    /**
     * The claim as stored now.
     *
     * @return \SineMacula\Laravel\Sso\Models\Domain
     */
    private function claim(): Domain
    {
        return Domain::query()->whereKey($this->domain->id)->sole();
    }

    /**
     * The connection's links version as stored now.
     *
     * @return int
     */
    private function linksVersion(): int
    {
        return Connection::query()->whereKey($this->connection->id)->sole()->links_version;
    }

    /**
     * The states of the connection's rows, sorted.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return list<string>
     */
    private function statesIn(Connection $connection): array
    {
        $states = array_map(static fn (Link $link): string => $link->state->value, Link::query()->where('connection_id', $connection->id)->get()->all());

        sort($states);

        return $states;
    }

    /**
     * A row of its own identity in the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $subject
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkState  $state
     * @param  ?int  $expiresIn
     * @param  ?string  $domainId
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    private function row(Connection $connection, string $subject, LinkState $state, ?int $expiresIn = null, ?string $domainId = null): Link
    {
        $key  = new LinkSubject(VerifyingDriver::ISSUER, $subject);
        $link = new Link;

        $link->forceFill([
            'connection_id'          => $connection->id,
            'issuer'                 => $key->issuer,
            'subject'                => $key->subject,
            'subject_key'            => $key->key(),
            'identity_type'          => 'App\Models\User',
            'identity_id'            => 'identity-' . $subject,
            'state'                  => $state,
            'provenance'             => LinkOrigin::VERIFIED_DOMAIN,
            'reservation_id'         => $expiresIn === null ? null : strtolower((string) Str::ulid()),
            'reservation_expires_at' => $expiresIn === null ? null : $this->clock->now()->addSeconds($expiresIn),
            'reservation_domain_id'  => $domainId,
        ])->save();

        return $link;
    }
}
