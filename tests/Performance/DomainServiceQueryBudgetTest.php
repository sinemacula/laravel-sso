<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Domains\DomainFinder;
use SineMacula\Laravel\Sso\Domains\DomainResult;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Domains\DomainSummary;
use SineMacula\Laravel\Sso\Domains\Enums\DomainStatus;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Freshness\RecordingFreshness;

/**
 * Query budgets for the domain helpers (SSO-3.1, SSO-3.2, SSO-11.8). Every
 * change reads the connection, and the claim when it acts on one, before
 * freshness is asked, then again in its transaction under the connection's
 * lock, and writes only what it changes:
 *
 * - `claim()`: 3 reads (the connection; then, locked, the connection and every
 *   claim of the domain), 1 write (the insert);
 * - `verify()`: 4 reads (the connection and the claim; then, locked, the
 *   connection and every claim of the domain), the domain check counted (an
 *   update, and an insert the first time), and 1 write (the update);
 * - `remove()`: 4 reads (the connection and the claim, twice), 1 write (the
 *   delete);
 * - `get()` and `list()`: 2 reads (the connection, then its claims), no write.
 *
 * A refusal stops where it is decided, with no write of a claim: a stale caller
 * costs the reads before freshness was asked, a verified domain is unchanged
 * after them, and a failed lookup after its domain check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainService::class)]
#[CoversClass(DomainFinder::class)]
final class DomainServiceQueryBudgetTest extends PerformanceContractTestCase
{
    use UsesConnections;

    /** @var string The tenant whose connection the helpers act on. */
    private const string TENANT = 'tenant-1';

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract the helpers ask. */
    private RecordingFreshness $freshness;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeDnsResolver The resolver the helpers look records up through. */
    private FakeDnsResolver $dns;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The tenant's connection. */
    private Connection $connection;

    /**
     * Bind a freshness contract that answers `fresh` and a fake resolver, and
     * make a connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freshness = new RecordingFreshness;
        $this->dns       = new FakeDnsResolver;

        $this->app?->instance(Freshness::class, $this->freshness);
        $this->app?->instance(DnsResolver::class, $this->dns);

        $this->connection = $this->makeConnection();
    }

    /**
     * A claim is three reads and an insert; a duplicate the same reads and no
     * write; a stale caller one read.
     *
     * @return void
     */
    public function testAClaimIsThreeReadsAndAnInsert(): void
    {
        $claimed   = $this->assertQueryBudget(3, 1, fn (): DomainResult => $this->claimDomain());
        $duplicate = $this->assertQueryBudget(3, 0, fn (): DomainResult => $this->claimDomain());

        $this->freshness->answer(FreshnessOutcome::STALE);

        $stale = $this->assertQueryBudget(1, 0, fn (): DomainResult => $this->claimDomain('example.org'));

        self::assertSame(DomainStatus::CLAIMED, $claimed->status);
        self::assertTrue($duplicate->isInvalid());
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $stale->reason);
    }

    /**
     * A verification is four reads, its domain check, and an update: the first
     * check of a connection creates its counter, a later one is one update.
     *
     * @return void
     */
    public function testAVerificationIsFourReadsItsCheckAndAnUpdate(): void
    {
        $this->dns->publishes(self::summaryOf($this->claimDomain()));

        $verified = $this->assertQueryBudget(4, 3, fn (): DomainResult => $this->verifyDomain());

        self::assertSame(DomainStatus::VERIFIED, $verified->status);

        $this->dns->publishes(self::summaryOf($this->claimDomain('example.org')));

        $again = $this->assertQueryBudget(4, 2, fn (): DomainResult => $this->verifyDomain('example.org'));

        self::assertSame(DomainStatus::VERIFIED, $again->status);
    }

    /**
     * A verified domain is unchanged after two reads; a failed lookup is
     * refused after two reads and its check.
     *
     * @return void
     */
    public function testARefusedVerificationWritesNoClaim(): void
    {
        $this->dns->publishes(self::summaryOf($this->claimDomain()));
        $this->verifyDomain();

        $unchanged = $this->assertQueryBudget(2, 0, fn (): DomainResult => $this->verifyDomain());

        $this->claimDomain('example.org');
        $this->dns->failing('_sso-verification.example.org');

        $failed = $this->assertQueryBudget(2, 1, fn (): DomainResult => $this->verifyDomain('example.org'));

        self::assertSame(DomainStatus::UNCHANGED, $unchanged->status);
        self::assertSame(FailureReason::DOMAIN_LOOKUP_FAILED, $failed->reason);
    }

    /**
     * A removal is four reads and a delete.
     *
     * @return void
     */
    public function testARemovalIsFourReadsAndADelete(): void
    {
        $this->claimDomain();

        $removed = $this->assertQueryBudget(4, 2, fn (): DomainResult => $this->domains()->remove(self::TENANT, $this->connection->id, 'example.com'));

        self::assertSame(DomainStatus::REMOVED, $removed->status);
    }

    /**
     * Reading one claim, or every claim of a connection, is two reads.
     *
     * @return void
     */
    public function testReadingIsTwoReads(): void
    {
        $this->claimDomain();
        $this->claimDomain('example.org');

        $read   = $this->assertQueryBudget(2, 0, fn (): ?DomainSummary => $this->domains()->get(self::TENANT, $this->connection->id, 'example.com'));
        $listed = $this->assertQueryBudget(2, 0, fn (): ?array => $this->domains()->list(self::TENANT, $this->connection->id));

        self::assertNotNull($read);
        self::assertCount(2, $listed ?? []);
    }

    /**
     * Claim the domain for the tenant's connection.
     *
     * @param  string  $domain
     * @return \SineMacula\Laravel\Sso\Domains\DomainResult
     */
    private function claimDomain(string $domain = 'example.com'): DomainResult
    {
        return $this->domains()->claim(self::TENANT, $this->connection->id, $domain);
    }

    /**
     * Verify the tenant's connection's claim of the domain.
     *
     * @param  string  $domain
     * @return \SineMacula\Laravel\Sso\Domains\DomainResult
     */
    private function verifyDomain(string $domain = 'example.com'): DomainResult
    {
        return $this->domains()->verify(self::TENANT, $this->connection->id, $domain);
    }

    /**
     * The domain helpers, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Domains\DomainService
     */
    private function domains(): DomainService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(DomainService::class);
    }

    /**
     * The summary a successful result carries.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\DomainResult  $result
     * @return \SineMacula\Laravel\Sso\Domains\DomainSummary
     */
    private static function summaryOf(DomainResult $result): DomainSummary
    {
        self::assertNotNull($result->domain);

        return $result->domain;
    }
}
