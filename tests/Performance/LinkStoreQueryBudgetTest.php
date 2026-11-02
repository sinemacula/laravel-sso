<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkCreationStatus;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkCreation;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkResult;
use SineMacula\Laravel\Sso\Links\LinkService;
use SineMacula\Laravel\Sso\Links\LinkStore;
use SineMacula\Laravel\Sso\Links\LinkSubject;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\Fixtures\Results\ExampleResults;

/**
 * Query budgets for the link store and helper (SSO-8.2 to SSO-8.4, SSO-11.3). A
 * resolution is one locking read, and one conditional update when it finds a
 * link, whether or not a minute has passed since its last use; a creation locks
 * the connection and the identity's links, inserts and raises the connection's
 * links version; a removal reads the link, then locks the connection and the
 * link and deletes it:
 *
 * - `resolve()` that finds a link: 1 read and 1 write; that finds none: 1 read;
 * - `create()`: 2 reads (the connection, the identity's links, both locked) and
 *   2 writes (the insert and the links version); refused by the unique index:
 *   the 2 reads and the insert; at the limit: the 2 reads alone;
 * - `remove()`: 3 reads (the link; then, locked, the connection and the link)
 *   and 1 write (the delete); a link not found: 1 read; a stale caller: 1 read;
 * - `list()`: 2 reads (the links, then their connections); with no link: 1.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkStore::class)]
#[CoversClass(LinkService::class)]
final class LinkStoreQueryBudgetTest extends PerformanceContractTestCase
{
    use UsesConnections;

    /** @var string The issuer every subject is from. */
    private const string ISSUER = 'https://idp.example.com';

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract the removal asks. */
    private RecordingFreshness $freshness;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection links are made through. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The identity links are made for. */
    private IdentityReference $identity;

    /**
     * Bind a freshness contract that answers `fresh` and make a connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freshness = new RecordingFreshness;

        $this->app?->instance(Freshness::class, $this->freshness);

        $this->connection = $this->makeConnection(['enabled' => true]);
        $this->identity   = new IdentityReference('user', '1');
    }

    /**
     * A resolution that finds a link is one locking read and one conditional
     * update, again within the minute; one that finds none is the read alone.
     *
     * @return void
     */
    public function testAResolutionIsOneReadAndAtMostOneWrite(): void
    {
        $this->createLink('subject-1');

        $first  = $this->assertQueryBudget(1, 1, fn (): LinkResolution => $this->store()->resolve($this->resultFor('subject-1')));
        $second = $this->assertQueryBudget(1, 1, fn (): LinkResolution => $this->store()->resolve($this->resultFor('subject-1')));
        $miss   = $this->assertQueryBudget(1, 0, fn (): LinkResolution => $this->store()->resolve($this->resultFor('subject-2')));

        self::assertSame('1', $first->identity?->id);
        self::assertSame('1', $second->identity?->id);
        self::assertTrue($miss->isAbsent());
    }

    /**
     * A creation is two locking reads, the insert and the raise of the links
     * version; one refused by the unique index is the reads and the insert; one
     * at the limit is the reads alone.
     *
     * @return void
     */
    public function testACreationIsThreeReadsTheInsertAndTheVersion(): void
    {
        $created   = $this->assertQueryBudget(3, 2, fn (): LinkCreation => $this->createLink('subject-1'));
        $duplicate = $this->assertQueryBudget(3, 1, fn (): LinkCreation => $this->createLink('subject-1', new IdentityReference('user', '2')));
        $limited   = $this->assertQueryBudget(2, 0, fn (): LinkCreation => $this->createLink('subject-2'));

        self::assertSame(LinkCreationStatus::CREATED, $created->status);
        self::assertSame(LinkCreationStatus::SUBJECT_ALREADY_LINKED, $duplicate->status);
        self::assertSame(LinkCreationStatus::LINK_LIMIT_REACHED, $limited->status);
    }

    /**
     * A removal is three reads and the delete; a link not found and a stale
     * caller stop at the first read.
     *
     * @return void
     */
    public function testARemovalIsThreeReadsAndTheDelete(): void
    {
        $id = (string) $this->createLink('subject-1')->link?->id;

        $missing = $this->assertQueryBudget(1, 0, fn (): LinkResult => $this->service()->remove(new IdentityReference('user', '2'), $id));

        $this->freshness->answer(FreshnessOutcome::STALE);

        $stale = $this->assertQueryBudget(1, 0, fn (): LinkResult => $this->service()->remove($this->identity, $id));

        $this->freshness->answer(FreshnessOutcome::FRESH);

        $removed = $this->assertQueryBudget(3, 2, fn (): LinkResult => $this->service()->remove($this->identity, $id));

        self::assertTrue($missing->isRefused());
        self::assertTrue($stale->isRefused());
        self::assertTrue($removed->isRemoved());
    }

    /**
     * A list is two reads, the links and their connections; with no link, the
     * first alone.
     *
     * @return void
     */
    public function testAListIsTwoReads(): void
    {
        $none = $this->assertQueryBudget(1, 0, fn (): array => $this->service()->list($this->identity));

        $this->createLink('subject-1');

        $listed = $this->assertQueryBudget(2, 0, fn (): array => $this->service()->list('me', $this->identity));

        self::assertSame([], $none);
        self::assertCount(1, $listed);
    }

    /**
     * Link the subject through the connection, to the identity given or the
     * test's.
     *
     * @param  string  $subject
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \SineMacula\Laravel\Sso\Links\LinkCreation
     */
    private function createLink(string $subject, ?IdentityReference $identity = null): LinkCreation
    {
        return $this->store()->create($this->connection, new LinkSubject(self::ISSUER, $subject), $identity ?? $this->identity, LinkOrigin::LINK_PURPOSE);
    }

    /**
     * A verified result through the connection with the subject given.
     *
     * @param  string  $subject
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    private function resultFor(string $subject): VerifiedResult
    {
        return new VerifiedResult(
            self::ISSUER,
            $subject,
            null,
            $this->connection->id,
            $this->connection->tenant_id,
            $this->connection->protocol,
            'web',
            Purpose::SIGN_IN,
            RequestReference::fromString(ExampleResults::REFERENCE),
            [],
            false,
            new AuthenticationContext,
        );
    }

    /**
     * The link store, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Links\LinkStore
     */
    private function store(): LinkStore
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(LinkStore::class);
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
