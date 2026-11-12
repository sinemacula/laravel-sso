<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\LinkSuspended;
use SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;
use SineMacula\Laravel\Sso\Linking\IdentityLock;
use SineMacula\Laravel\Sso\Linking\ScopeWidening;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Links\NoLinks;
use SineMacula\Laravel\Sso\Links\ReservationWithdrawal;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\IdentityGuard;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;
use Tests\Concerns\ComparesIdentitiesWithoutCase;
use Tests\Concerns\RecordsLockOrder;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Enforcement\FailingRevocation;
use Tests\Fixtures\Enforcement\TableSessions;
use Tests\Fixtures\Links\DelegatingLinkStorage;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Feature tests for what an application's principal mutation calls.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ScopeWidening::class)]
#[CoversClass(IdentityLock::class)]
#[CoversClass(IdentityGuard::class)]
#[CoversClass(LinkCandidatesChanged::class)]
#[CoversClass(RevocationScope::class)]
#[CoversClass(RevocationScopeKind::class)]
#[CoversClass(RevocationReason::class)]
#[CoversClass(ReservationWithdrawal::class)]
#[CoversClass(LinkStore::class)]
final class ScopeWideningTest extends LinkingTestCase
{
    use ComparesIdentitiesWithoutCase, RecordsLockOrder;

    /** @var object{scopes: list<\SineMacula\Laravel\Sso\Revocation\RevocationScope>, levels: list<int>} The revocation, recording each scope and its level. */
    private object $revocation;

    /**
     * Bind a revocation that records each call.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->revocation = new class implements SessionRevocation {
            /** @var list<\SineMacula\Laravel\Sso\Revocation\RevocationScope> Each scope, in order. */
            public array $scopes = [];

            /** @var list<int> The transaction level of each call, in order. */
            public array $levels = [];

            /**
             * Record the call.
             *
             * @param  \SineMacula\Laravel\Sso\Revocation\RevocationScope  $scope
             * @return void
             */
            #[\Override]
            public function revoke(RevocationScope $scope): void
            {
                $this->scopes[] = $scope;
                $this->levels[] = DB::connection(StorageConnection::name())->transactionLevel();
            }
        };

        $this->app?->instance(SessionRevocation::class, $this->revocation);
    }

    /**
     * Outside a transaction on the storage connection, it refuses, and takes no
     * guard.
     *
     * @return void
     */
    public function testItNeedsATransaction(): void
    {
        try {
            app(ScopeWidening::class)->widened([$this->person], 'tenant-2', Clients::browser());
            self::fail('It widened with no transaction open.');
        } catch (\LogicException $exception) {
            self::assertSame(
                'A widened scope is reported inside the transaction that changes the person\'s principals, on the storage connection (decision D5).',
                $exception->getMessage(),
            );
        }

        self::assertSame(0, IdentityGuard::query()->count());
    }

    /**
     * A principal of another tenant suspends the link and revokes its sessions
     * inside the transaction.
     *
     * @return void
     */
    public function testAPrincipalOfAnotherTenantSuspendsTheLinkAndRevokes(): void
    {
        $link    = $this->activeDomainLink();
        $version = Connection::query()->whereKey($this->connection->id)->sole()->links_version;
        $before  = count($this->recordedEvents());

        $answer = $this->connection->getConnection()->transaction(function () use ($before): int {

            $suspended = app(ScopeWidening::class)->widened([$this->person], 'tenant-2', Clients::browser());

            self::assertCount($before, $this->recordedEvents());

            return $suspended;
        });

        $row = Link::query()->sole();

        self::assertSame(1, $answer);
        self::assertSame(LinkState::SUSPENDED, $row->state);
        self::assertSame($this->clock->now()->toIso8601String(), $row->suspended_at?->toIso8601String());
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN, $row->provenance);
        self::assertSame($version + 1, Connection::query()->whereKey($this->connection->id)->sole()->links_version);

        self::assertCount(1, $this->revocation->scopes);
        self::assertSame(1, $this->revocation->levels[0]);

        $scope = $this->revocation->scopes[0];

        self::assertSame(RevocationScopeKind::IDENTITY_LINK, $scope->kind);
        self::assertSame(RevocationReason::SCOPE_WIDENED, $scope->reason);
        self::assertSame('tenant-1', $scope->tenantId);
        self::assertSame($this->connection->id, $scope->connectionId);
        self::assertSame($this->person->jsonSerialize(), $scope->identity?->jsonSerialize());
        self::assertSame($link->id, $scope->linkId);
        self::assertNull($scope->policy);

        $events = array_slice($this->recordedEvents(), $before);

        self::assertCount(1, $events);
        self::assertInstanceOf(LinkSuspended::class, $events[0]);
        self::assertSame($this->connection->id, $events[0]->context->connectionId);
        self::assertSame('tenant-1', $events[0]->context->connectionTenantId);
        self::assertSame(VerifyingDriver::NAME, $events[0]->context->protocol);
        self::assertSame($this->person->id, $events[0]->context->identityId);
    }

    /**
     * An adapter holding sessions by the link that established them loses only
     * those: another session through the same connection stands.
     *
     * @return void
     */
    public function testOnlyTheSessionsOfTheAffectedLinkAreRevoked(): void
    {
        TableSessions::create();

        $this->app?->instance(SessionRevocation::class, new TableSessions);

        $link = $this->activeDomainLink();

        TableSessions::write('tenant-1', $this->connection->id, $link->id);
        TableSessions::write('tenant-1', $this->connection->id);

        self::assertSame(1, $this->widen([$this->person], 'tenant-2'));

        $left = DB::connection(StorageConnection::name())->table(TableSessions::TABLE)->pluck('link_id')->all();

        TableSessions::drop();

        self::assertSame([null], $left);
    }

    /**
     * A platform principal, given as `null`, is outside every tenant.
     *
     * @return void
     */
    public function testAPlatformPrincipalIsOutsideEveryTenant(): void
    {
        $this->activeDomainLink();

        self::assertSame(1, $this->widen([$this->person], null));
        self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);
    }

    /**
     * A principal of the connection's own tenant leaves it alone; tenants are
     * compared exactly, so another case is another tenant.
     *
     * @return void
     */
    public function testAPrincipalOfTheSameTenantLeavesTheLinkAlone(): void
    {
        $this->activeDomainLink();

        self::assertSame(0, $this->widen([$this->person], 'tenant-1'));
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
        self::assertSame([], $this->revocation->scopes);

        self::assertSame(1, $this->widen([$this->person], 'TENANT-1'));
        self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);
    }

    /**
     * A principal added and removed between checks leaves the link suspended.
     *
     * @return void
     */
    public function testAPrincipalAddedAndRemovedBetweenChecksIsCaught(): void
    {
        $this->activeDomainLink();

        $this->widen([$this->person], 'tenant-2');

        self::assertSame(ScopeVerdict::WITHIN_TENANT, $this->scope->verdict);

        $this->start();

        self::assertSame(FailureReason::LINK_SUSPENDED, $this->complete()->reason);
        self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);
    }

    /**
     * A reservation is deleted by a widening and never activates.
     *
     * @return void
     */
    public function testAReservationIsDeletedAndNeverActivates(): void
    {
        $start      = $this->start();
        $completion = $this->complete();
        $version    = Connection::query()->whereKey($this->connection->id)->sole()->links_version;

        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);
        self::assertSame(0, $this->widen([$this->person], 'tenant-2'));
        self::assertSame(0, Link::query()->count());
        self::assertSame($version + 1, Connection::query()->whereKey($this->connection->id)->sole()->links_version);
        self::assertSame([], $this->revocation->scopes);
        self::assertSame(FailureReason::RESERVATION_INVALID, $this->admit($completion, $start)->reason);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * An already suspended link only has its sessions revoked again.
     *
     * @return void
     */
    public function testAnAlreadySuspendedLinkHasItsSessionsRevokedOnly(): void
    {
        $link = $this->activeDomainLink();

        $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT;

        $this->start();
        $this->complete();

        $version = Connection::query()->whereKey($this->connection->id)->sole()->links_version;
        $events  = count($this->recordedEvents());
        $stamped = Link::query()->sole()->suspended_at;

        $this->clock->advance(30);

        $linkIds = static fn (array $scopes): array => array_map(static fn (RevocationScope $scope): ?string => $scope->linkId, $scopes);

        self::assertSame([$link->id], $linkIds($this->revocation->scopes), 'The resolution that latched it revoked.');

        self::assertSame(0, $this->widen([$this->person], 'tenant-2'));
        self::assertSame([$link->id, $link->id], $linkIds($this->revocation->scopes));
        self::assertSame($version, Connection::query()->whereKey($this->connection->id)->sole()->links_version);
        self::assertCount($events, $this->recordedEvents());
        self::assertSame($stamped?->toIso8601String(), Link::query()->sole()->suspended_at?->toIso8601String());
    }

    /**
     * A latch outside any transaction locks the connection before the link.
     *
     * @return void
     */
    public function testALatchOutsideAnyTransactionLocksTheConnectionFirst(): void
    {
        $link    = $this->activeDomainLink();
        $version = Connection::query()->whereKey($this->connection->id)->sole()->links_version;
        $before  = count($this->recordedEvents());

        $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT;

        $this->recordLockOrder();

        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        self::assertTrue(app(LinkStore::class)->resolve($this->resultOfTheLink(), Clients::browser())->isSuspended());
        self::assertSame(['link', 'connections ' . $this->connection->id . ', tenant-1', 'link'], $this->lockOrder());

        $events = array_slice($this->recordedEvents(), $before);

        self::assertCount(1, $events);
        self::assertInstanceOf(LinkSuspended::class, $events[0]);
        self::assertSame([$link->id], array_map(static fn (RevocationScope $scope): ?string => $scope->linkId, $this->revocation->scopes));
        self::assertSame([1], $this->revocation->levels);
        self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);
        self::assertSame($version + 1, Connection::query()->whereKey($this->connection->id)->sole()->links_version);
    }

    /**
     * A latch another resolution made first is not made again.
     *
     * @return void
     */
    public function testALatchAnotherResolutionMadeFirstIsNotMadeAgain(): void
    {
        $link    = $this->activeDomainLink();
        $before  = count($this->recordedEvents());
        $table   = StorageConnection::table('links.table');
        $latched = false;

        $this->scope->verdict = ScopeVerdict::OUTSIDE_TENANT;

        DB::connection(StorageConnection::name())->listen(function (QueryExecuted $query) use ($link, $table, &$latched): void {

            if ($latched || !str_starts_with(strtolower($query->sql), 'select') || !str_contains($query->sql, $table)) {
                return;
            }

            $latched = true;

            Link::query()->whereKey($link->id)->update(['state' => LinkState::SUSPENDED->value, 'suspended_at' => '2026-11-01 09:00:00']);
        });

        $version = Connection::query()->whereKey($this->connection->id)->sole()->links_version;
        $answer  = app(LinkStore::class)->resolve($this->resultOfTheLink(), Clients::browser());

        self::assertTrue($latched);
        self::assertTrue($answer->isSuspended());
        self::assertSame($link->id, $answer->linkId);
        self::assertSame([], array_slice($this->recordedEvents(), $before));
        self::assertSame([], $this->revocation->scopes);
        self::assertSame($version, Connection::query()->whereKey($this->connection->id)->sole()->links_version);
        self::assertSame('2026-11-01T09:00:00+00:00', Link::query()->sole()->suspended_at?->toIso8601String());
    }

    /**
     * A link of any other provenance is left: it never stood on the domain.
     *
     * @return void
     */
    public function testALinkOfAnotherProvenanceIsLeft(): void
    {
        foreach ([LinkOrigin::PROVISIONING, LinkOrigin::LINK_PURPOSE, LinkOrigin::MIGRATION] as $index => $origin) {

            $identity = new IdentityReference('App\Models\User', 'other-' . $index);

            app(LinkStore::class)->create($this->connection, new LinkSubject(VerifyingDriver::ISSUER, 'subject-' . $index), $identity, $origin, Clients::browser());

            self::assertSame(0, $this->widen([new IdentityReference('App\Models\User', 'other-' . $index)], 'tenant-2'));
        }

        self::assertSame(3, Link::query()->where('state', LinkState::ACTIVE->value)->count());
        self::assertSame([], $this->revocation->scopes);
    }

    /**
     * Another identity's links are left, the identity compared byte for byte.
     *
     * @return void
     */
    public function testAnotherIdentitysLinkIsLeft(): void
    {
        $this->activeDomainLink();

        self::assertSame(0, $this->widen([new IdentityReference('App\Models\User', '8')], 'tenant-2'));
        self::assertSame(0, $this->widen([new IdentityReference('App\Models\Admin', $this->person->id)], 'tenant-2'));
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
    }

    /**
     * Every connection holding the identity's rows is locked in one statement,
     * in id order.
     *
     * @return void
     */
    public function testTheLockOrder(): void
    {
        $ids = [];

        foreach (['tenant-2', 'tenant-3'] as $tenant) {

            $connection = $this->connectionOf($tenant);
            $ids[]      = $connection->id;

            $this->domainRowIn($connection, 'subject-in-' . $tenant);
        }

        $mine = $this->connectionOf('tenant-9');

        $this->domainRowIn($mine, 'subject-in-mine');

        $all = [...$ids, $mine->id];

        sort($ids, SORT_STRING);
        sort($all, SORT_STRING);

        $this->recordLockOrder();

        self::assertSame(2, $this->widen([$this->person], 'tenant-9'));
        self::assertSame(['identity guard', 'connections ' . implode(', ', $all), 'link'], $this->lockOrder());
        self::assertSame($ids, array_map(static fn (RevocationScope $scope): ?string => $scope->connectionId, $this->revocation->scopes));
        self::assertSame(LinkState::ACTIVE, Link::query()->where('connection_id', $mine->id)->sole()->state);
    }

    /**
     * A revocation that fails rolls the suspension back, reports nothing and
     * propagates.
     *
     * @return void
     */
    public function testARevocationThatFailsRollsItBack(): void
    {
        $this->activeDomainLink();

        $this->app?->instance(SessionRevocation::class, new FailingRevocation);

        $version = Connection::query()->whereKey($this->connection->id)->sole()->links_version;
        $events  = count($this->recordedEvents());

        try {
            $this->widen([$this->person], 'tenant-2');
            self::fail('The failure did not propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame(FailingRevocation::MESSAGE, $exception->getMessage());
        }

        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
        self::assertNull(Link::query()->sole()->suspended_at);
        self::assertSame($version, Connection::query()->whereKey($this->connection->id)->sole()->links_version);
        self::assertCount($events, $this->recordedEvents());
    }

    /**
     * A row the plain read missed refuses the whole change for a retry.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARowItsFirstReadMissedRefusesTheWholeChange(): void
    {
        $other    = $this->connectionOf('tenant-2');
        $database = $this->connection->getConnection();
        $inserted = false;

        $database->listen(function (QueryExecuted $query) use ($other, &$inserted): void {

            if ($inserted || !str_contains($query->sql, StorageConnection::table('links.table')) || !str_starts_with(strtolower($query->sql), 'select')) {
                return;
            }

            $inserted = true;

            $this->domainRowIn($other, 'a-subject');
        });

        try {
            $database->transaction(fn (): int => app(ScopeWidening::class)->widened([$this->person], 'tenant-9', Clients::browser()));
            self::fail('The change went on over what it missed.');
        } catch (LinkCandidatesChanged $exception) {
            self::assertSame('An identity\'s verified domain links changed before they were locked; retry the whole transaction.', $exception->getMessage());
        }

        self::assertSame([], $this->revocation->scopes);
        self::assertSame(0, Link::query()->count(), 'The row made in that transaction rolls back with it.');

        $this->domainRowIn($other, 'a-subject');

        self::assertSame(1, $this->widen([$this->person], 'tenant-9'));
        self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);
    }

    /**
     * The guard is the identity's: one row per identity, however often it is
     * taken, naming nobody, and another identity has another.
     *
     * @return void
     */
    public function testTheGuardIsTheIdentitys(): void
    {
        $this->widen([$this->person], 'tenant-2');
        $this->widen([$this->person], 'tenant-3');

        $guard = IdentityGuard::query()->sole();

        self::assertSame(IdentityLock::digest($this->person), $guard->identity_hash);
        self::assertSame(64, strlen($guard->identity_hash));
        self::assertSame($this->clock->now()->toIso8601String(), $guard->created_at->toIso8601String());

        $this->widen([new IdentityReference('App\Models\User', '8')], 'tenant-2');

        self::assertSame(2, IdentityGuard::query()->count());
        self::assertNotSame(IdentityLock::digest(new IdentityReference('ab', 'c')), IdentityLock::digest(new IdentityReference('a', 'bc')));
        self::assertNotSame(IdentityLock::digest(new IdentityReference('a', 'B')), IdentityLock::digest(new IdentityReference('a', 'b')));
    }

    /**
     * Over a linker not backed by link storage it takes the guard and changes
     * nothing, since such a linker holds no link by a verified domain.
     *
     * @return void
     */
    public function testALinkerNotBackedByStorageHasNothingToSuspend(): void
    {
        $row = $this->domainRowIn($this->connectionOf('tenant-2'), 'a-subject');

        $this->app?->instance(Linker::class, new NoLinks);

        self::assertSame(0, $this->widen([$this->person], 'tenant-9'));
        self::assertSame(LinkState::ACTIVE, $row->refresh()->state);
        self::assertSame(1, IdentityGuard::query()->count());
    }

    /**
     * A wrapper that delegates to the store suspends and revokes through it.
     *
     * @return void
     */
    public function testAWrapperThatDelegatesSuspendsAndRevokes(): void
    {
        $row = $this->domainRowIn($this->connectionOf('tenant-2'), 'a-subject');

        $this->app?->instance(Linker::class, new DelegatingLinkStorage(app(LinkStore::class)));

        self::assertSame(1, $this->widen([$this->person], 'tenant-9'));
        self::assertSame(LinkState::SUSPENDED, $row->refresh()->state);
        self::assertSame([$row->id], array_map(static fn (RevocationScope $scope): ?string => $scope->linkId, $this->revocation->scopes));
    }

    /**
     * A row an engine's collation finds, of an identity differing only in case,
     * is another person's: it is neither suspended nor revoked.
     *
     * @return void
     */
    public function testARowDifferingOnlyInTheCaseOfItsIdentityIsLeft(): void
    {
        $this->compareIdentityIdsWithoutCase();

        $person = new IdentityReference($this->person->type, 'ada');
        $other  = $this->domainRowIn($this->connectionOf('tenant-2'), 'subject-of-another-person');

        $other->forceFill(['identity_id' => 'ADA'])->save();

        self::assertSame(0, $this->widen([$person], 'tenant-9'));
        self::assertSame(LinkState::ACTIVE, $other->refresh()->state);
        self::assertSame([], $this->revocation->scopes);
    }

    /**
     * Sharing a connection with such a row changes nothing for it: only the
     * identity's own link is suspended and revoked.
     *
     * @return void
     */
    public function testARowDifferingOnlyInCaseIsLeftInAConnectionOfTheIdentitysOwn(): void
    {
        $this->compareIdentityIdsWithoutCase();

        $person     = new IdentityReference($this->person->type, 'ada');
        $connection = $this->connectionOf('tenant-2');
        $other      = $this->domainRowIn($connection, 'subject-of-another-person');
        $own        = $this->domainRowIn($connection, 'subject-of-this-person');

        $other->forceFill(['identity_id' => 'ADA'])->save();
        $own->forceFill(['identity_id' => 'ada'])->save();

        self::assertSame(1, $this->widen([$person], 'tenant-9'));
        self::assertSame(LinkState::ACTIVE, $other->refresh()->state);
        self::assertSame(LinkState::SUSPENDED, $own->refresh()->state);
        self::assertSame([$own->id], array_map(static fn (RevocationScope $scope): ?string => $scope->linkId, $this->revocation->scopes));
    }

    /**
     * An identity with nothing by a verified domain costs its guard and two
     * reads of its rows, and none of a connection.
     *
     * @return void
     */
    public function testAnIdentityHoldingNothingReadsNoConnection(): void
    {
        $database = $this->connection->getConnection();

        $database->enableQueryLog();
        $database->flushQueryLog();

        self::assertSame(0, $this->widen([$this->person], 'tenant-9'));
        self::assertCount(3, $database->getQueryLog());
    }

    /**
     * Several identities are widened in one call, and the total is answered.
     *
     * @return void
     */
    public function testSeveralIdentitiesAreWidenedInOneCall(): void
    {
        $other = new IdentityReference('App\Models\User', '8');
        $mine  = $this->domainRowIn($this->connectionOf('tenant-9'), 'subject-in-mine');
        $rows  = [
            $this->domainRowIn($this->connectionOf('tenant-2'), 'subject-of-the-person'),
            $this->domainRowIn($this->connectionOf('tenant-3'), 'subject-of-another', LinkState::ACTIVE, $other),
        ];

        self::assertSame(2, $this->widen([$this->person, $other], 'tenant-9'));

        foreach ($rows as $row) {
            self::assertSame(LinkState::SUSPENDED, $row->refresh()->state);
        }

        self::assertSame(LinkState::ACTIVE, $mine->refresh()->state);
        self::assertEqualsCanonicalizing(
            [$this->person->jsonSerialize(), $other->jsonSerialize()],
            array_map(static fn (RevocationScope $scope): ?array => $scope->identity?->jsonSerialize(), $this->revocation->scopes),
        );
    }

    /**
     * An identity given twice is guarded, read and counted once.
     *
     * @return void
     */
    public function testAnIdentityGivenTwiceIsTakenOnce(): void
    {
        $connection = $this->connectionOf('tenant-2');

        $this->domainRowIn($connection, 'a-subject');
        $this->recordLockOrder();

        self::assertSame(1, $this->widen([$this->person, $this->person], 'tenant-9'));
        self::assertSame(['identity guard', 'connections ' . $connection->id, 'link'], $this->lockOrder());
        self::assertCount(1, $this->revocation->scopes);
    }

    /**
     * The guards are taken first, in ascending order of their digests, however
     * the identities are given.
     *
     * @return void
     */
    public function testTheGuardsAreTakenInAscendingOrderOfTheirDigests(): void
    {
        $identities = array_map(static fn (string $id): IdentityReference => new IdentityReference('App\Models\User', $id), ['7', '8', '9', '10', '11']);

        usort($identities, static fn (IdentityReference $a, IdentityReference $b): int => strcmp(IdentityLock::digest($b), IdentityLock::digest($a)));

        $expected = array_map(IdentityLock::digest(...), $identities);
        $digests  = [];
        $table    = StorageConnection::table('identity_guards.table');

        sort($expected, SORT_STRING);

        $this->connection->getConnection()->listen(static function (QueryExecuted $query) use ($table, &$digests): void {

            if (!str_starts_with(strtolower($query->sql), 'insert') || !str_contains($query->sql, $table)) {
                return;
            }

            $hashes    = array_filter($query->bindings, static fn (mixed $binding): bool => is_string($binding) && preg_match('/^[0-9a-f]{64}$/', $binding) === 1);
            $digests[] = array_values($hashes)[0] ?? null;
        });

        self::assertNotSame($expected, array_map(IdentityLock::digest(...), $identities));
        self::assertSame(0, $this->widen($identities, 'tenant-9'));
        self::assertSame($expected, $digests);
    }

    /**
     * The identities' connections are locked in one statement, after every
     * guard.
     *
     * @return void
     */
    public function testTheUnionOfTheirConnectionsIsLockedInOneStatement(): void
    {
        $other  = new IdentityReference('App\Models\User', '8');
        $first  = $this->connectionOf('tenant-2');
        $shared = $this->connectionOf('tenant-3');
        $last   = $this->connectionOf('tenant-4');

        $this->domainRowIn($first, 'subject-of-the-person');
        $this->domainRowIn($shared, 'another-subject-of-the-person');
        $this->domainRowIn($shared, 'subject-of-another', LinkState::ACTIVE, $other);
        $this->domainRowIn($last, 'another-subject-of-another', LinkState::ACTIVE, $other);

        $ids = [$first->id, $shared->id, $last->id];

        sort($ids, SORT_STRING);

        $this->recordLockOrder();

        self::assertSame(4, $this->widen([$other, $this->person], 'tenant-9'));
        self::assertSame(['identity guard', 'identity guard', 'connections ' . implode(', ', $ids), 'link'], $this->lockOrder());
    }

    /**
     * A row of one identity its plain read missed refuses the whole change
     * before anything of another identity is changed or revoked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUncoveredRowOfOneIdentityChangesNothingOfAnother(): void
    {
        $other    = new IdentityReference('App\Models\User', '8');
        $missed   = $this->connectionOf('tenant-3');
        $database = $this->connection->getConnection();
        $inserted = false;

        $this->domainRowIn($this->connectionOf('tenant-2'), 'subject-of-the-person');

        $database->listen(function (QueryExecuted $query) use ($missed, $other, &$inserted): void {

            if ($inserted || !str_contains($query->sql, StorageConnection::table('links.table')) || !str_starts_with(strtolower($query->sql), 'select')) {
                return;
            }

            $inserted = true;

            $this->domainRowIn($missed, 'subject-of-another', LinkState::ACTIVE, $other);
        });

        $this->expectException(LinkCandidatesChanged::class);

        try {
            $this->widen([$this->person, $other], 'tenant-9');
        } finally {
            self::assertTrue($inserted);
            self::assertSame([], $this->revocation->scopes);
            self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
        }
    }

    /**
     * An empty list is no change: it answers 0 and runs no statement, inside a
     * transaction or not.
     *
     * @return void
     */
    public function testAnEmptyListChangesNothing(): void
    {
        $this->domainRowIn($this->connectionOf('tenant-2'), 'a-subject');

        $database = $this->connection->getConnection();

        $database->enableQueryLog();
        $database->flushQueryLog();

        self::assertSame(0, app(ScopeWidening::class)->widened([], 'tenant-9', Clients::browser()));
        self::assertSame(0, $this->widen([], 'tenant-9'));
        self::assertSame([], $database->getQueryLog());
        self::assertSame(0, IdentityGuard::query()->count());
        self::assertSame([], $this->revocation->scopes);
    }

    /**
     * Its reads name exactly the identities given, and the provenance.
     *
     * @return void
     */
    public function testItReadsOnlyTheRowsOfTheIdentitiesGiven(): void
    {
        $other    = new IdentityReference('App\Models\Admin', '8');
        $database = $this->connection->getConnection();
        $table    = StorageConnection::table('links.table');

        $database->enableQueryLog();
        $database->flushQueryLog();

        self::assertSame(0, $this->widen([$this->person, $other], 'tenant-9'));

        $reads = array_values(array_filter($database->getQueryLog(), static fn (array $query): bool => str_contains($query['query'], $table)));

        self::assertCount(2, $reads);

        foreach ($reads as $read) {
            self::assertEqualsCanonicalizing([$this->person->type, $this->person->id, $other->type, $other->id, LinkOrigin::VERIFIED_DOMAIN->value], $read['bindings']);
        }
    }

    /**
     * Rows of `[the state of the row made first, of the row made second]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Links\Enums\LinkState, 1: \SineMacula\Laravel\Sso\Links\Enums\LinkState}>
     */
    public static function provideOrders(): iterable
    {
        yield 'the reservation first' => [LinkState::RESERVED, LinkState::ACTIVE];
        yield 'the link first' => [LinkState::ACTIVE, LinkState::RESERVED];
    }

    /**
     * A connection's reservation and link are each dealt with, whichever is
     * read first.
     *
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkState  $first
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkState  $second
     * @return void
     */
    #[DataProvider('provideOrders')]
    public function testEveryRowIsDealtWithWhateverComesFirst(LinkState $first, LinkState $second): void
    {
        $connection = $this->connectionOf('tenant-2');

        $this->domainRowIn($connection, 'subject-made-first', $first);
        $this->domainRowIn($connection, 'subject-made-second', $second);

        self::assertSame(1, $this->widen([$this->person], 'tenant-9'));

        $link = Link::query()->sole();

        self::assertSame(LinkState::SUSPENDED, $link->state);
        self::assertCount(1, $this->revocation->scopes);
        self::assertSame($link->id, $this->revocation->scopes[0]->linkId);
    }

    /**
     * `RevocationScope::identityLink()` refuses what it cannot name.
     *
     * @return void
     */
    public function testALinkScopeNamesWhatItRevokes(): void
    {
        $unnamed = 'A revocation scope names its tenant and connection.';

        foreach ([['', 'c', 'l', $unnamed], ['t', '', 'l', $unnamed], ['t', 'c', '', 'A revocation scope of a link names the link.']] as [$tenant, $connection, $link, $message]) {

            try {
                RevocationScope::identityLink($tenant, $connection, $this->person, $link);
                self::fail('It named nothing.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame($message, $exception->getMessage());
            }
        }
    }

    /**
     * A connection of the tenant.
     *
     * @param  string  $tenant
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function connectionOf(string $tenant): Connection
    {
        return $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'enabled' => true, 'tenant_id' => $tenant, 'settings' => ['issuer' => VerifyingDriver::ISSUER]]);
    }

    /**
     * Report the widening of the identities, in a transaction.
     *
     * @param  list<\SineMacula\Laravel\Sso\Identities\IdentityReference>  $identities
     * @param  ?string  $tenantId
     * @return int
     */
    private function widen(array $identities, ?string $tenantId): int
    {
        return $this->connection->getConnection()->transaction(static fn (): int => app(ScopeWidening::class)->widened($identities, $tenantId, Clients::browser()));
    }

    /**
     * An active link with verified domain provenance, through the machine.
     *
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    private function activeDomainLink(): Link
    {
        $start = $this->start();

        self::assertTrue($this->admit($this->complete(), $start)->isRedeemed());

        return Link::query()->sole();
    }

    /**
     * A `sign_in` result of the driver's subject through the connection.
     *
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    private function resultOfTheLink(): VerifiedResult
    {
        return new VerifiedResult(
            issuer: VerifyingDriver::ISSUER,
            subject: VerifyingDriver::SUBJECT,
            nameIdFormat: null,
            connectionId: $this->connection->id,
            tenantId: 'tenant-1',
            protocol: VerifyingDriver::NAME,
            application: 'web',
            purpose: Purpose::SIGN_IN,
            requestReference: RequestReference::fromString('Dq8tVv3w0kLmNoPqRsTuVwXyZ0123456'),
            attributes: [],
            emailDomainVerified: false,
            authenticationContext: new AuthenticationContext,
        );
    }

    /**
     * A row of the identity, the person unless given, with verified domain
     * provenance in the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $subject
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkState  $state
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    private function domainRowIn(Connection $connection, string $subject, LinkState $state = LinkState::ACTIVE, ?IdentityReference $identity = null): Link
    {
        $identity ??= $this->person;
        $key  = new LinkSubject(VerifyingDriver::ISSUER, $subject);
        $link = new Link;

        $link->forceFill([
            'connection_id'          => $connection->id,
            'issuer'                 => $key->issuer,
            'subject'                => $key->subject,
            'subject_key'            => $key->key(),
            'identity_type'          => $identity->type,
            'identity_id'            => $identity->id,
            'state'                  => $state,
            'provenance'             => LinkOrigin::VERIFIED_DOMAIN,
            'reservation_id'         => $state === LinkState::RESERVED ? strtolower((string) Str::ulid()) : null,
            'reservation_expires_at' => $state === LinkState::RESERVED ? $this->clock->now()->addMinute() : null,
        ])->save();

        return $link;
    }
}
