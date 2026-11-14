<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Identities\Caller;
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
use Tests\Fixtures\Clients;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\Fixtures\Results\ExampleResults;

/**
 * Query budgets for the link store and link helper.
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
     * Answer `fresh` to every freshness check and make a connection.
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
     * One locking read and one conditional update, again within the minute; a
     * miss is the read alone.
     *
     * @return void
     */
    public function testAResolutionIsOneReadAndAtMostOneWrite(): void
    {
        $this->createLink('subject-1');

        $first  = $this->assertQueryBudget(1, 1, fn (): LinkResolution => $this->store()->resolve($this->resultFor('subject-1'), Clients::browser()));
        $second = $this->assertQueryBudget(1, 1, fn (): LinkResolution => $this->store()->resolve($this->resultFor('subject-1'), Clients::browser()));
        $miss   = $this->assertQueryBudget(1, 0, fn (): LinkResolution => $this->store()->resolve($this->resultFor('subject-2'), Clients::browser()));

        self::assertSame('1', $first->identity?->id);
        self::assertSame('1', $second->identity?->id);
        self::assertTrue($miss->isAbsent());
    }

    /**
     * The connection, links and reservation locked, the insert and links
     * version; a duplicate stops at the insert, a full identity at two reads.
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
     * The link, then the connection and link locked, the delete and the links
     * version; a link not found stops at the first read, a stale caller at the
     * locks.
     *
     * @return void
     */
    public function testARemovalIsThreeReadsAndTheDelete(): void
    {
        $id = (string) $this->createLink('subject-1')->link?->id;

        $missing = $this->assertQueryBudget(1, 0, fn (): LinkResult => $this->service()->remove(new IdentityReference('user', '2'), $id, Clients::browser()));

        $this->freshness->answer(FreshnessOutcome::STALE);

        $stale = $this->assertQueryBudget(3, 0, fn (): LinkResult => $this->service()->remove($this->identity, $id, Clients::browser()));

        $this->freshness->answer(FreshnessOutcome::FRESH);

        $removed = $this->assertQueryBudget(3, 2, fn (): LinkResult => $this->service()->remove($this->identity, $id, Clients::browser()));

        self::assertTrue($missing->isRefused());
        self::assertTrue($stale->isRefused());
        self::assertTrue($removed->isRemoved());
    }

    /**
     * The links, then their connections; with no link, the first alone.
     *
     * @return void
     */
    public function testAListIsTwoReads(): void
    {
        $none = $this->assertQueryBudget(1, 0, fn (): array => $this->service()->list($this->identity));

        $this->createLink('subject-1');

        $listed = $this->assertQueryBudget(2, 0, fn (): array => $this->service()->list('me', new Caller($this->identity)));

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
        return $this->store()->create($this->connection, new LinkSubject(self::ISSUER, $subject), $identity ?? $this->identity, LinkOrigin::LINK_PURPOSE, Clients::browser());
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
