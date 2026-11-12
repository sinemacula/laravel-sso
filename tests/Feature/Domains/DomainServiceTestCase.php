<?php

declare(strict_types = 1);

namespace Tests\Feature\Domains;

use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Domains\DomainResult;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Domains\DomainSummary;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Testing\FakeDnsResolver;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\TestCase;

/**
 * Shared set-up for the domain helper feature tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class DomainServiceTestCase extends TestCase
{
    use RecordsEventSequences, UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The tenant whose connection the helpers act on. */
    protected const string TENANT = 'tenant-1';

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    protected FixedClock $clock;

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract the helpers ask. */
    protected RecordingFreshness $freshness;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeDnsResolver The resolver the helpers look records up through. */
    protected FakeDnsResolver $dns;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The tenant's connection. */
    protected Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Identities\Caller Who makes each change. */
    protected Caller $actor;

    /**
     * Bind the clock, freshness and resolver, create the tables and connection,
     * and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock     = new FixedClock('2026-11-01T09:30:00Z');
        $this->freshness = new RecordingFreshness;
        $this->dns       = new FakeDnsResolver;
        $this->actor     = new Caller(new IdentityReference('App\Models\User', '42'));

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Freshness::class, $this->freshness);
        $this->app?->instance(DnsResolver::class, $this->dns);

        $this->usePackageTables();

        $this->connection = $this->makeConnection();

        $this->startRecordingEvents();
    }

    /**
     * The domain helpers, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Domains\DomainService
     */
    protected function domains(): DomainService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(DomainService::class);
    }

    /**
     * Claim the domain for the tenant's connection, by the acting identity.
     *
     * @param  string  $domain
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Domains\DomainResult
     */
    protected function claimDomain(string $domain = 'example.com', ?Connection $connection = null): DomainResult
    {
        $connection ??= $this->connection;

        return $this->domains()->claim($connection->tenant_id, $connection->id, $domain, Clients::browser(), $this->actor);
    }

    /**
     * Verify the tenant's connection's claim of the domain, by the acting
     * identity.
     *
     * @param  string  $domain
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return \SineMacula\Laravel\Sso\Domains\DomainResult
     */
    protected function verifyDomain(string $domain = 'example.com', ?Connection $connection = null): DomainResult
    {
        $connection ??= $this->connection;

        return $this->domains()->verify($connection->tenant_id, $connection->id, $domain, Clients::browser(), $this->actor);
    }

    /**
     * The summary a successful result carries.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\DomainResult  $result
     * @return \SineMacula\Laravel\Sso\Domains\DomainSummary
     */
    protected static function summaryOf(DomainResult $result): DomainSummary
    {
        static::assertNotNull($result->domain, 'The result carries no domain: ' . json_encode($result));

        return $result->domain;
    }
}
