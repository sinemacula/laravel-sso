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
use Tests\Fixtures\Clients;
use Tests\Fixtures\Freshness\RecordingFreshness;

/**
 * Query budgets for the domain helpers.
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
     * Answer `fresh` to every freshness check, bind a fake resolver and make a
     * connection.
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
     * The connection, then it and the domain's claims locked, and the insert; a
     * duplicate writes nothing, a stale caller reads once.
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
     * The connection and claim, both again locked, the domain check's counter
     * (an insert too the first time) and the update.
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
     * The connection and claim, both again locked, and the delete.
     *
     * @return void
     */
    public function testARemovalIsFourReadsAndADelete(): void
    {
        $this->claimDomain();

        $removed = $this->assertQueryBudget(4, 2, fn (): DomainResult => $this->domains()->remove(self::TENANT, $this->connection->id, 'example.com', Clients::browser()));

        self::assertSame(DomainStatus::REMOVED, $removed->status);
    }

    /**
     * The connection, then one claim or all of them.
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
        return $this->domains()->claim(self::TENANT, $this->connection->id, $domain, Clients::browser());
    }

    /**
     * Verify the tenant's connection's claim of the domain.
     *
     * @param  string  $domain
     * @return \SineMacula\Laravel\Sso\Domains\DomainResult
     */
    private function verifyDomain(string $domain = 'example.com'): DomainResult
    {
        return $this->domains()->verify(self::TENANT, $this->connection->id, $domain, Clients::browser());
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
