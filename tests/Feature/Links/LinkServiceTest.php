<?php

declare(strict_types = 1);

namespace Tests\Feature\Links;

use Carbon\CarbonImmutable;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\Grammars\SQLiteGrammar;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SessionRevocation;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\LinkRemoved;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Links\LinkEvents;
use SineMacula\Laravel\Sso\Links\LinkResult;
use SineMacula\Laravel\Sso\Links\LinkService;
use SineMacula\Laravel\Sso\Links\LinkSummary;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesEnforcement;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Enforcement\RecordingRevocation;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\TestCase;

/**
 * Feature tests for the link helper (SSO-8.4, SSO-4.5, SSO-1.5, SSO-2.12,
 * SSO-10.3): an identity's links listed by reference or as `me`, oldest first
 * and without the subject; and a removal that finds the identity's own link,
 * asks freshness, deletes it under its connection's lock, revokes the
 * identity's sessions through the connection in the same transaction and
 * reports it, while each refusal deletes, revokes and reports nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkService::class)]
#[CoversClass(LinkResult::class)]
#[CoversClass(LinkSummary::class)]
#[CoversClass(LinkEvents::class)]
final class LinkServiceTest extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesEnforcement, UsesFlowTables;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract the helper asks. */
    private RecordingFreshness $freshness;

    /** @var \Tests\Fixtures\Enforcement\RecordingRevocation The revocation the helper calls. */
    private RecordingRevocation $revocation;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection links are made through. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The identity whose links are listed and removed. */
    private IdentityReference $identity;

    /**
     * Bind the clock, the freshness contract and the revocation, create the
     * tables and a connection, and record events.
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

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Freshness::class, $this->freshness);
        $this->app?->instance(SessionRevocation::class, $this->revocation);

        $this->createConnectionTables();
        $this->createEnforcementTable();
        $this->createFlowTables();

        $this->connection = $this->makeConnection(['enabled' => true]);
        $this->identity   = new IdentityReference('user', '1');

        $this->startRecordingEvents();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropFlowTables();
        $this->dropEnforcementTable();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * The identity's links in every tenant's connections are listed, with each
     * connection's tenant and protocol and no subject; another identity's are
     * not.
     *
     * @return void
     */
    public function testListsTheIdentitysLinksAcrossTenants(): void
    {
        $foreign = $this->makeConnection(['enabled' => true, 'tenant_id' => 'tenant-2', 'protocol' => 'saml2']);

        $local = $this->makeLink($this->connection, 'subject-1');

        $this->clock->advance(60);

        $remote = $this->makeLink($foreign, 'subject-2', ['name_id_format' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', 'provenance' => LinkOrigin::VERIFIED_DOMAIN]);

        $this->makeLink($this->connection, 'subject-3', ['identity_id' => '2']);

        $listed = array_map(static fn (LinkSummary $summary): array => $summary->jsonSerialize(), $this->service()->list($this->identity));

        self::assertSame([
            [
                'id'                => $local->id,
                'connection_id'     => $this->connection->id,
                'tenant_id'         => 'tenant-1',
                'protocol'          => 'oidc',
                'issuer'            => 'https://idp.example.com',
                'name_id_format'    => null,
                'state'             => 'active',
                'domain_provenance' => false,
                'created_at'        => '2026-11-01T09:30:00Z',
                'last_used_at'      => null,
            ],
            [
                'id'                => $remote->id,
                'connection_id'     => $foreign->id,
                'tenant_id'         => 'tenant-2',
                'protocol'          => 'saml2',
                'issuer'            => 'https://idp.example.com',
                'name_id_format'    => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
                'state'             => 'active',
                'domain_provenance' => true,
                'created_at'        => '2026-11-01T09:31:00Z',
                'last_used_at'      => null,
            ],
        ], $listed);
    }

    /**
     * `me` lists the caller's links, and a reference given with a caller lists
     * the reference's.
     *
     * @return void
     */
    public function testMeListsTheCallersLinks(): void
    {
        $mine   = $this->makeLink($this->connection, 'subject-1');
        $theirs = $this->makeLink($this->connection, 'subject-2', ['identity_id' => '2']);

        $other = new IdentityReference('user', '2');

        self::assertSame([$mine->id], self::ids($this->service()->list('me', $this->identity)));
        self::assertSame([$theirs->id], self::ids($this->service()->list($other, $this->identity)));
        self::assertSame([], $this->service()->list(new IdentityReference('user', '3')));
    }

    /**
     * Links are listed by creation time, oldest first, and by id among links
     * created in the same second.
     *
     * @return void
     */
    public function testListsOldestFirstThenById(): void
    {
        $earliest = $this->makeLink($this->connection, 'subject-1', ['id' => '01jbzzzzzzzzzzzzzzzzzzzzz5']);

        $this->clock->advance(1);

        $later  = $this->makeLink($this->connection, 'subject-2', ['id' => '01jbzzzzzzzzzzzzzzzzzzzzz9']);
        $sooner = $this->makeLink($this->connection, 'subject-3', ['id' => '01jbzzzzzzzzzzzzzzzzzzzzz1']);

        self::assertSame([$earliest->id, $sooner->id, $later->id], self::ids($this->service()->list($this->identity)));
    }

    /**
     * A link whose connection no longer exists is left out of the list.
     *
     * @return void
     */
    public function testALinkWithoutItsConnectionIsNotListed(): void
    {
        $kept = $this->makeLink($this->connection, 'subject-1');

        $this->makeLink($this->connection, 'subject-2', ['connection_id' => '01jbzzzzzzzzzzzzzzzzzzzzzz']);

        self::assertSame([$kept->id], self::ids($this->service()->list($this->identity)));
    }

    /**
     * Rows of `[identity, caller, message]`: an identity that names no one.
     *
     * @return iterable<string, array{string, ?\SineMacula\Laravel\Sso\Identities\IdentityReference, string}>
     */
    public static function provideUnnamed(): iterable
    {
        yield '`me` without a caller' => ['me', null, 'The identity [me] names the caller, and no caller was given.'];
        yield 'another string' => ['you', new IdentityReference('user', '1'), 'An identity is a reference, or [me] for the caller.'];
        yield '`me` in upper case' => ['ME', new IdentityReference('user', '1'), 'An identity is a reference, or [me] for the caller.'];
        yield 'an empty string' => ['', null, 'An identity is a reference, or [me] for the caller.'];
    }

    /**
     * Listing for an identity that names no one is an invalid argument.
     *
     * @param  string  $identity
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideUnnamed')]
    public function testListingForNoOneIsRefused(string $identity, ?IdentityReference $caller, string $message): void
    {
        $this->expectExceptionObject(new \InvalidArgumentException($message));

        $this->service()->list($identity, $caller);
    }

    /**
     * Removing for an identity that names no one is an invalid argument, with
     * nothing asked or removed.
     *
     * @param  string  $identity
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @param  string  $message
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideUnnamed')]
    public function testRemovingForNoOneIsRefused(string $identity, ?IdentityReference $caller, string $message): void
    {
        $link = $this->makeLink($this->connection);

        try {
            $this->service()->remove($identity, $link->id, $caller);
            self::fail('The removal succeeded.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame($message, $exception->getMessage());
        }

        self::assertSame([], $this->freshness->asked());
        self::assertSame(1, Link::query()->count());
    }

    /**
     * A removal deletes the link, asks freshness once, revokes the identity's
     * sessions through the connection inside the transaction, reports it once,
     * and answers the link as it was. Removing the last link is allowed.
     *
     * @return void
     */
    public function testRemovesTheLinkRevokesAndReports(): void
    {
        $link = $this->makeLink($this->connection, 'subject-1', ['last_used_at' => CarbonImmutable::parse('2026-11-01T09:00:00Z')]);

        $result = $this->service()->remove($this->identity, $link->id, null, new ActingIdentity('App\Models\User', '42'));

        self::assertTrue($result->isRemoved());
        self::assertSame([
            'removed' => true,
            'link'    => [
                'id'                => $link->id,
                'connection_id'     => $this->connection->id,
                'tenant_id'         => 'tenant-1',
                'protocol'          => 'oidc',
                'issuer'            => 'https://idp.example.com',
                'name_id_format'    => null,
                'state'             => 'active',
                'domain_provenance' => false,
                'created_at'        => '2026-11-01T09:30:00Z',
                'last_used_at'      => '2026-11-01T09:00:00Z',
            ],
            'reason' => null,
        ], $result->jsonSerialize());

        self::assertSame(0, Link::query()->count());
        self::assertSame([[FreshnessOperation::LINK_REMOVE, 300]], $this->freshness->asked());

        $calls = $this->revocation->calls();

        self::assertCount(1, $calls);
        self::assertSame(1, $calls[0]['level']);

        $scope = $calls[0]['scope'];

        self::assertSame(RevocationScopeKind::IDENTITY_CONNECTION, $scope->kind);
        self::assertSame(RevocationReason::LINK_REMOVED, $scope->reason);
        self::assertSame('tenant-1', $scope->tenantId);
        self::assertSame($this->connection->id, $scope->connectionId);
        self::assertSame(['type' => 'user', 'id' => '1'], $scope->identity?->jsonSerialize());
        self::assertNull($scope->policy);

        $this->assertEventSequence([LinkRemoved::class]);

        $context = $this->recordedEvents()[0]->context();

        self::assertSame($this->connection->id, $context->connectionId);
        self::assertSame('tenant-1', $context->tenantId);
        self::assertSame('oidc', $context->protocol);
        self::assertSame('user', $context->identityMorphClass);
        self::assertSame('1', $context->identityId);
        self::assertSame('App\Models\User', $context->actingIdentityMorphClass);
        self::assertSame('42', $context->actingIdentityId);
        self::assertNull($context->application);
        self::assertNull($context->purpose);
        self::assertNull($context->requestReference);
        self::assertSame([], $this->service()->list($this->identity));
    }

    /**
     * A removal raises the connection's links version by exactly one, so a flow
     * that read the link before it fails to serialise rather than miss it.
     *
     * @return void
     */
    public function testARemovalRaisesTheLinksVersion(): void
    {
        $link   = $this->makeLink($this->connection, 'subject-1');
        $before = Connection::query()->whereKey($this->connection->id)->sole()->links_version;

        self::assertTrue($this->service()->remove($this->identity, $link->id, null, new ActingIdentity('App\Models\User', '42'))->isRemoved());
        self::assertSame($before + 1, Connection::query()->whereKey($this->connection->id)->sole()->links_version);
    }

    /**
     * `me` removes the caller's link, and with no acting identity the event
     * names none.
     *
     * @return void
     */
    public function testMeRemovesTheCallersLink(): void
    {
        $link = $this->makeLink($this->connection);

        $result = $this->service()->remove('me', $link->id, $this->identity);

        self::assertTrue($result->isRemoved());
        self::assertSame($link->id, $result->link?->id);
        self::assertSame(0, Link::query()->count());

        $context = $this->recordedEvents()[0]->context();

        self::assertNull($context->actingIdentityMorphClass);
        self::assertNull($context->actingIdentityId);
    }

    /**
     * Only the removed link goes: the identity's other links, and another
     * identity's in the same connection, stay.
     *
     * @return void
     */
    public function testOnlyTheLinkGiven(): void
    {
        $removed = $this->makeLink($this->connection, 'subject-1');
        $kept    = $this->makeLink($this->connection, 'subject-2');
        $theirs  = $this->makeLink($this->connection, 'subject-3', ['identity_id' => '2']);

        self::assertTrue($this->service()->remove($this->identity, $removed->id)->isRemoved());

        $left = Link::query()->orderBy('id')->pluck('id')->all();

        self::assertEqualsCanonicalizing([$kept->id, $theirs->id], $left);
    }

    /**
     * Rows of `[how the link is named]`: a link that is not the identity's.
     *
     * @return iterable<string, array{string}>
     */
    public static function provideNotFound(): iterable
    {
        yield 'another identity\'s link' => ['theirs'];
        yield 'another type\'s link' => ['another type'];
        yield 'an id no link has' => ['unknown'];
        yield 'an empty id' => ['empty'];
    }

    /**
     * A link that is another identity's is refused exactly as one that does not
     * exist, with nothing asked, deleted, revoked or reported.
     *
     * @param  string  $which
     * @return void
     */
    #[DataProvider('provideNotFound')]
    public function testAnotherIdentitysLinkIsNotFound(string $which): void
    {
        $theirs  = $this->makeLink($this->connection, 'subject-1', ['identity_id' => '2']);
        $another = $this->makeLink($this->connection, 'subject-2', ['identity_type' => 'admin']);

        $id = match ($which) {
            'theirs'       => $theirs->id,
            'another type' => $another->id,
            'unknown'      => '01jbzzzzzzzzzzzzzzzzzzzzzz',
            default        => '',
        };

        $result = $this->service()->remove($this->identity, $id);

        self::assertSame(['removed' => false, 'link' => null, 'reason' => 'link_not_found'], $result->jsonSerialize());
        $this->assertNothingChanged(2);
        self::assertSame([], $this->freshness->asked());
    }

    /**
     * A caller who is not fresh enough is refused, with nothing deleted,
     * revoked or reported.
     *
     * @return void
     */
    public function testAStaleCallerIsRefused(): void
    {
        $this->freshness->answer(FreshnessOutcome::STALE);

        $link = $this->makeLink($this->connection);

        $result = $this->service()->remove($this->identity, $link->id);

        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $result->reason);
        self::assertNull($result->link);
        self::assertSame([[FreshnessOperation::LINK_REMOVE, 300]], $this->freshness->asked());
        $this->assertNothingChanged(1);
    }

    /**
     * A link removed or given to another identity after it was first read is
     * found gone by the locking read, and nothing is revoked or reported.
     *
     * @return void
     */
    public function testALinkThatChangedBeforeTheLockIsNotFound(): void
    {
        $gone = $this->makeLink($this->connection, 'subject-1');

        $this->freshness->onCheck = static function () use ($gone): void {
            Link::query()->whereKey($gone->id)->delete();
        };

        self::assertSame(FailureReason::LINK_NOT_FOUND, $this->service()->remove($this->identity, $gone->id)->reason);
        $this->assertNothingChanged(0);

        $moved = $this->makeLink($this->connection, 'subject-2');

        $this->freshness->onCheck = static function () use ($moved): void {
            Link::query()->whereKey($moved->id)->update(['identity_id' => '2']);
        };

        self::assertSame(FailureReason::LINK_NOT_FOUND, $this->service()->remove($this->identity, $moved->id)->reason);
        $this->assertNothingChanged(1);
        self::assertSame('2', Link::query()->sole()->identity_id);
    }

    /**
     * The link is read twice: first plainly, before the freshness contract is
     * asked; then, inside the removal's transaction, with a locking read, so a
     * caller's older snapshot never decides the delete, the revocation or the
     * report.
     *
     * @return void
     */
    public function testTheLinkIsReadAgainWithALockInsideTheTransaction(): void
    {
        $link       = $this->makeLink($this->connection, 'subject-1');
        $statements = $this->recordLinkStatements();

        self::assertTrue($this->service()->remove($this->identity, $link->id)->isRemoved());
        self::assertSame([
            ['transaction' => false, 'locked' => false],
            ['transaction' => true, 'locked' => true],
        ], $statements->getArrayCopy());
    }

    /**
     * A link whose connection no longer exists is not found, and is left as it
     * is.
     *
     * @return void
     */
    public function testALinkWithoutItsConnectionIsNotFound(): void
    {
        $orphan = $this->makeLink($this->connection, 'subject-1', ['connection_id' => '01jbzzzzzzzzzzzzzzzzzzzzzz']);

        $result = $this->service()->remove($this->identity, $orphan->id);

        self::assertSame(FailureReason::LINK_NOT_FOUND, $result->reason);
        self::assertSame([[FreshnessOperation::LINK_REMOVE, 300]], $this->freshness->asked());
        $this->assertNothingChanged(1);
    }

    /**
     * A reserved link of the identity is removed like an active one.
     *
     * @return void
     */
    public function testAReservedLinkIsRemoved(): void
    {
        $link = $this->makeLink($this->connection, 'subject-1', [
            'state'                  => LinkState::RESERVED,
            'reservation_expires_at' => CarbonImmutable::parse('2026-11-01T09:35:00Z'),
        ]);

        $result = $this->service()->remove($this->identity, $link->id);

        self::assertSame(LinkState::RESERVED, $result->link?->state);
        self::assertSame(0, Link::query()->count());
        self::assertCount(1, $this->revocation->calls());
    }

    /**
     * Record each read of the links table from now on: whether it was made
     * inside a transaction, and whether it locked the rows for update; on
     * SQLite, with the lock compiled to a marker comment.
     *
     * @return \ArrayObject<int, array{transaction: bool, locked: bool}>
     */
    private function recordLinkStatements(): \ArrayObject
    {
        $database = DB::connection(StorageConnection::name());

        if ($database->getDriverName() === 'sqlite') {
            $database->setQueryGrammar(new class ($database) extends SQLiteGrammar {
                /**
                 * Compile a lock for update to a marker comment.
                 *
                 * @param  \Illuminate\Database\Query\Builder  $query
                 * @param  bool|string  $value
                 * @return string
                 */
                #[\Override]
                protected function compileLock(Builder $query, $value): string
                {
                    return $value === true ? ' /* for update */' : '';
                }
            });
        }

        $table = (new Link)->getTable();
        $level = $database->transactionLevel();

        /** @var \ArrayObject<int, array{transaction: bool, locked: bool}> $statements */
        $statements = new \ArrayObject;

        $database->listen(static function (QueryExecuted $query) use ($statements, $table, $level): void {

            $sql = strtolower($query->sql);

            if (!str_starts_with($sql, 'select') || !str_contains($sql, $table)) {
                return;
            }

            $statements[] = ['transaction' => $query->connection->transactionLevel() > $level, 'locked' => str_ends_with(rtrim($sql, ' */'), 'for update')];
        });

        return $statements;
    }

    /**
     * Assert no revocation was asked for and no event reported, and the links
     * left number as given.
     *
     * @param  int  $links
     * @return void
     */
    private function assertNothingChanged(int $links): void
    {
        self::assertSame($links, Link::query()->count());
        self::assertSame([], $this->revocation->calls());
        $this->assertNoEvents();
    }

    /**
     * The ids of the summaries, in order.
     *
     * @param  list<\SineMacula\Laravel\Sso\Links\LinkSummary>  $summaries
     * @return list<string>
     */
    private static function ids(array $summaries): array
    {
        return array_map(static fn (LinkSummary $summary): string => $summary->id, $summaries);
    }

    /**
     * The link helper, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Links\LinkService
     */
    private function service(): LinkService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(LinkService::class);
    }
}
