<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\LinkSuspended;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;
use SineMacula\Laravel\Sso\Linking\ScopeWidening;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Links\ReservationWithdrawal;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;
use Tests\Concerns\ComparesIdentitiesWithoutCase;
use Tests\Concerns\RecordsLockOrder;
use Tests\Fixtures\Enforcement\FailingRevocation;
use Tests\Fixtures\Enforcement\TableSessions;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Feature tests for what an application's principal mutation calls (SSO-8.8):
 * inside its transaction, an identity's links by a verified domain in every
 * connection of another tenant are suspended for good and the sessions
 * established through them revoked; its reservations in them are deleted, so a
 * principal added and removed between checks is caught; links of any other
 * provenance, identity or tenant are left; the lock order; a revocation that
 * fails rolls it back; and `assertSettled()` catches what its first read
 * missed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ScopeWidening::class)]
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
     * Outside a transaction on the storage connection, each refuses.
     *
     * @return void
     */
    public function testEachNeedsATransaction(): void
    {
        $message = 'A widened scope is reported inside the transaction that changes the person\'s principals, on the storage connection (decision D5).';

        try {
            app(ScopeWidening::class)->widened($this->person, 'tenant-2');
            self::fail('It widened with no transaction open.');
        } catch (\LogicException $exception) {
            self::assertSame($message, $exception->getMessage());
        }

        try {
            app(ScopeWidening::class)->assertSettled($this->person, 'tenant-2');
            self::fail('It settled with no transaction open.');
        } catch (\LogicException $exception) {
            self::assertSame($message, $exception->getMessage());
        }
    }

    /**
     * A principal of another tenant suspends the link, stored and latched,
     * raises the links version, reports it after commit, and revokes the
     * sessions established through exactly it, inside the transaction.
     *
     * @return void
     */
    public function testAPrincipalOfAnotherTenantSuspendsTheLinkAndRevokes(): void
    {
        $link    = $this->activeDomainLink();
        $version = Connection::query()->whereKey($this->connection->id)->sole()->links_version;
        $before  = count($this->recordedEvents());

        $answer = $this->connection->getConnection()->transaction(function () use ($before): int {

            $suspended = app(ScopeWidening::class)->widened($this->person, 'tenant-2');

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
        self::assertSame($this->person, $scope->identity);
        self::assertSame($link->id, $scope->linkId);
        self::assertNull($scope->policy);

        $events = array_slice($this->recordedEvents(), $before);

        self::assertCount(1, $events);
        self::assertInstanceOf(LinkSuspended::class, $events[0]);
        self::assertSame($this->connection->id, $events[0]->context->connectionId);
        self::assertSame('tenant-1', $events[0]->context->tenantId);
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

        self::assertSame(1, $this->widen($this->person, 'tenant-2'));

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

        self::assertSame(1, $this->widen($this->person, null));
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

        self::assertSame(0, $this->widen($this->person, 'tenant-1'));
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
        self::assertSame([], $this->revocation->scopes);

        self::assertSame(1, $this->widen($this->person, 'TENANT-1'));
        self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);
    }

    /**
     * A principal added and removed between checks is caught: every later check
     * answers `within_tenant`, and still the link stays suspended, resolving
     * nothing, until a confirming `link`.
     *
     * @return void
     */
    public function testAPrincipalAddedAndRemovedBetweenChecksIsCaught(): void
    {
        $this->activeDomainLink();

        $this->widen($this->person, 'tenant-2');

        self::assertSame(ScopeVerdict::WITHIN_TENANT, $this->scope->verdict);

        $this->start();

        self::assertSame(FailureReason::LINK_SUSPENDED, $this->complete()->reason);
        self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);
    }

    /**
     * A reservation made before the principal cannot activate once it is
     * removed: it is deleted, raising the links version, with nothing to
     * revoke; its code meets `reservation_invalid`.
     *
     * @return void
     */
    public function testAReservationIsDeletedAndNeverActivates(): void
    {
        $start      = $this->start();
        $completion = $this->complete();
        $version    = Connection::query()->whereKey($this->connection->id)->sole()->links_version;

        self::assertSame(LinkState::RESERVED, Link::query()->sole()->state);
        self::assertSame(0, $this->widen($this->person, 'tenant-2'));
        self::assertSame(0, Link::query()->count());
        self::assertSame($version + 1, Connection::query()->whereKey($this->connection->id)->sole()->links_version);
        self::assertSame([], $this->revocation->scopes);
        self::assertSame(FailureReason::RESERVATION_INVALID, $this->admit($completion, $start)->reason);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * A link suspended by a resolution revoked nothing then, so its sessions
     * are revoked now, with no second event and no version raised.
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

        self::assertSame(0, $this->widen($this->person, 'tenant-2'));
        self::assertSame([$link->id], array_map(static fn (RevocationScope $scope): ?string => $scope->linkId, $this->revocation->scopes));
        self::assertSame($version, Connection::query()->whereKey($this->connection->id)->sole()->links_version);
        self::assertCount($events, $this->recordedEvents());
        self::assertSame($stamped?->toIso8601String(), Link::query()->sole()->suspended_at?->toIso8601String());
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

            app(LinkStore::class)->create($this->connection, new LinkSubject(VerifyingDriver::ISSUER, 'subject-' . $index), $identity, $origin);

            self::assertSame(0, $this->widen(new IdentityReference('App\Models\User', 'other-' . $index), 'tenant-2'));
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

        self::assertSame(0, $this->widen(new IdentityReference('App\Models\User', '8'), 'tenant-2'));
        self::assertSame(0, $this->widen(new IdentityReference('App\Models\Admin', $this->person->id), 'tenant-2'));
        self::assertSame(LinkState::ACTIVE, Link::query()->sole()->state);
    }

    /**
     * Each connection of another tenant is taken in ascending id order, the
     * connection before its links, and a connection of the new principal's
     * tenant is never locked.
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

        sort($ids, SORT_STRING);

        $this->recordLockOrder();

        self::assertSame(2, $this->widen($this->person, 'tenant-9'));
        self::assertSame(['connections ' . $ids[0], 'link', 'connections ' . $ids[1], 'link'], $this->lockOrder());
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
            $this->widen($this->person, 'tenant-2');
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
     * Once `widened()` has run nothing stands in the way, so `assertSettled()`
     * passes, as it does for an identity with no links and for a connection of
     * the new principal's own tenant.
     *
     * @return void
     */
    public function testASettledChangePasses(): void
    {
        $this->activeDomainLink();

        $this->connection->getConnection()->transaction(function (): void {

            app(ScopeWidening::class)->assertSettled($this->person, 'tenant-1');
            app(ScopeWidening::class)->assertSettled(new IdentityReference('App\Models\User', '8'), 'tenant-2');
            app(ScopeWidening::class)->widened($this->person, 'tenant-2');
            app(ScopeWidening::class)->assertSettled($this->person, 'tenant-2');
        });

        self::assertSame(LinkState::SUSPENDED, Link::query()->sole()->state);
    }

    /**
     * A link or a reservation that appeared after `widened()` read refuses the
     * change, which rolls back to be retried; a retry reaches it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWhatAppearedSinceTheFirstReadRefusesTheChange(): void
    {
        foreach ([LinkState::ACTIVE, LinkState::RESERVED] as $state) {

            Link::query()->delete();

            $row = $this->domainRowIn($this->connection, 'a-subject', $state);

            try {
                $this->connection->getConnection()->transaction(function (): void {
                    app(ScopeWidening::class)->assertSettled($this->person, 'tenant-2');
                });

                self::fail('The change went on over what it missed.');
            } catch (\RuntimeException $exception) {
                self::assertSame('An identity\'s links changed while its scope widened; retry the whole transaction.', $exception->getMessage());
            }

            self::assertSame($state, Link::query()->whereKey($row->id)->sole()->state);
        }

        $this->connection->getConnection()->transaction(function (): void {
            app(ScopeWidening::class)->widened($this->person, 'tenant-2');
            app(ScopeWidening::class)->assertSettled($this->person, 'tenant-2');
        });

        self::assertSame(0, Link::query()->where('state', LinkState::RESERVED->value)->count());
    }

    /**
     * A link already suspended, and another provenance, do not refuse the
     * change.
     *
     * @return void
     */
    public function testOnlyActiveOrReservedDomainRowsAreUnsettled(): void
    {
        $this->domainRowIn($this->connection, 'a-suspended-subject', LinkState::SUSPENDED);

        $this->domainRowIn($this->connection, 'a-provisioned-subject')->forceFill(['provenance' => LinkOrigin::PROVISIONING])->save();

        $this->connection->getConnection()->transaction(function (): void {
            app(ScopeWidening::class)->assertSettled($this->person, 'tenant-2');
        });

        self::assertSame(2, Link::query()->count());
    }

    /**
     * A row an engine's collation finds, of an identity differing only in case,
     * is another person's: it is neither suspended nor revoked, and it never
     * unsettles the change.
     *
     * @return void
     */
    public function testARowDifferingOnlyInTheCaseOfItsIdentityIsLeft(): void
    {
        $this->compareIdentityIdsWithoutCase();

        $person = new IdentityReference($this->person->type, 'ada');
        $other  = $this->domainRowIn($this->connectionOf('tenant-2'), 'subject-of-another-person');

        $other->forceFill(['identity_id' => 'ADA'])->save();

        self::assertSame(0, $this->widen($person, 'tenant-9'));
        self::assertSame(LinkState::ACTIVE, $other->refresh()->state);
        self::assertSame([], $this->revocation->scopes);

        $this->connection->getConnection()->transaction(static function () use ($person): void {
            app(ScopeWidening::class)->assertSettled($person, 'tenant-9');
        });

        self::assertSame(LinkState::ACTIVE, $other->refresh()->state);
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

        self::assertSame(1, $this->widen($person, 'tenant-9'));
        self::assertSame(LinkState::ACTIVE, $other->refresh()->state);
        self::assertSame(LinkState::SUSPENDED, $own->refresh()->state);
        self::assertSame([$own->id], array_map(static fn (RevocationScope $scope): ?string => $scope->linkId, $this->revocation->scopes));
    }

    /**
     * An identity with nothing by a verified domain costs one read of its rows
     * and none of a connection, each way.
     *
     * @return void
     */
    public function testAnIdentityHoldingNothingReadsNoConnection(): void
    {
        $database = $this->connection->getConnection();

        $database->enableQueryLog();
        $database->flushQueryLog();

        self::assertSame(0, $this->widen($this->person, 'tenant-9'));
        self::assertCount(1, $database->getQueryLog());

        $database->flushQueryLog();

        $database->transaction(function (): void {
            app(ScopeWidening::class)->assertSettled($this->person, 'tenant-9');
        });

        self::assertCount(1, $database->getQueryLog());
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

        self::assertSame(1, $this->widen($this->person, 'tenant-9'));

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
     * Report the widening, in a transaction.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  ?string  $tenantId
     * @return int
     */
    private function widen(IdentityReference $identity, ?string $tenantId): int
    {
        return $this->connection->getConnection()->transaction(static fn (): int => app(ScopeWidening::class)->widened($identity, $tenantId));
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
     * A row of the person with verified domain provenance in the connection.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  string  $subject
     * @param  \SineMacula\Laravel\Sso\Links\Enums\LinkState  $state
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    private function domainRowIn(Connection $connection, string $subject, LinkState $state = LinkState::ACTIVE): Link
    {
        $key  = new LinkSubject(VerifyingDriver::ISSUER, $subject);
        $link = new Link;

        $link->forceFill([
            'connection_id'          => $connection->id,
            'issuer'                 => $key->issuer,
            'subject'                => $key->subject,
            'subject_key'            => $key->key(),
            'identity_type'          => $this->person->type,
            'identity_id'            => $this->person->id,
            'state'                  => $state,
            'provenance'             => LinkOrigin::VERIFIED_DOMAIN,
            'reservation_id'         => $state === LinkState::RESERVED ? strtolower((string) Str::ulid()) : null,
            'reservation_expires_at' => $state === LinkState::RESERVED ? $this->clock->now()->addMinute() : null,
        ])->save();

        return $link;
    }
}
