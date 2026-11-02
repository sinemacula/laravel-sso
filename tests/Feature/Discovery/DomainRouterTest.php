<?php

declare(strict_types = 1);

namespace Tests\Feature\Discovery;

use Carbon\CarbonImmutable;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Discovery\DomainRouter;
use SineMacula\Laravel\Sso\Domains\DomainClaims;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Protocols\StartingDriver;
use Tests\TestCase;

/**
 * Feature tests for resolving an email to the connection its domain routes
 * discovery to (SSO-3.4, SSO-3.5): a verified domain routes, before and within
 * the grace period that follows its record going, and not at or after its end;
 * a pending or lapsed claim, a disabled, incomplete or deleted connection, a
 * subdomain and an unknown domain all answer `null`; the domain is the part
 * after the last `@`, normalised by IDNA and in lower case; another tenant's
 * verified domain routes to that tenant's connection; and an email whose domain
 * does not normalise reads nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainRouter::class)]
#[CoversClass(DomainClaims::class)]
final class DomainRouterTest extends TestCase
{
    use UsesConnections, UsesDomains;

    /** @var string The instant the clock is fixed at. */
    private const string NOW = '2026-11-01T09:30:00Z';

    /** @var \SineMacula\Laravel\Sso\Models\Connection A usable connection of `tenant-1`. */
    private Connection $connection;

    /**
     * Bind a fixed clock, register the driver, create the tables and a usable
     * connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock(self::NOW));

        config()->set('sso.features.oidc', true);

        $driver = new StartingDriver;

        app(ProtocolManager::class)->extend(StartingDriver::NAME, fn (): StartingDriver => $driver);

        $this->createConnectionTables();
        $this->createDomainsTable();

        $this->connection = $this->usableConnection();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropDomainsTable();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * A verified domain routes to its usable connection, read afresh.
     *
     * @return void
     */
    public function testAVerifiedDomainRoutesToItsConnection(): void
    {
        $this->makeDomain($this->connection, 'example.com', ['state' => DomainState::VERIFIED]);

        $routed = $this->router()->connectionFor('someone@example.com');

        self::assertNotNull($routed);
        self::assertSame($this->connection->id, $routed->id);
        self::assertSame('tenant-1', $routed->tenant_id);
        self::assertNotSame($this->connection, $routed);
    }

    /**
     * Each instant a verified claim's grace period ends, and whether the claim
     * still routes then.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function graceEnds(): iterable
    {
        yield 'a day after now' => ['2026-11-02T09:30:00Z', true];
        yield 'one second after now' => ['2026-11-01T09:30:01Z', true];
        yield 'exactly now' => ['2026-11-01T09:30:00Z', false];
        yield 'one second before now' => ['2026-11-01T09:29:59Z', false];
    }

    /**
     * A verified domain whose record went still routes within its grace period,
     * linking suspended or not, and stops routing at its end, before any
     * recheck marks it lapsed.
     *
     * @param  string  $lapsesAt
     * @param  bool  $routes
     * @return void
     */
    #[DataProvider('graceEnds')]
    public function testAVerifiedDomainRoutesOnlyWithinItsGracePeriod(string $lapsesAt, bool $routes): void
    {
        $this->makeDomain($this->connection, 'example.com', [
            'state'                => DomainState::VERIFIED,
            'linking_suspended_at' => CarbonImmutable::parse('2026-11-01T09:00:00Z'),
            'lapses_at'            => CarbonImmutable::parse($lapsesAt),
        ]);

        self::assertSame($routes ? $this->connection->id : null, $this->router()->connectionFor('someone@example.com')?->id);
    }

    /**
     * A pending claim, unexpired or expired, does not route.
     *
     * @return void
     */
    public function testAPendingClaimDoesNotRoute(): void
    {
        $this->makeDomain($this->connection, 'example.com');
        $this->makeDomain($this->connection, 'expired.com', ['pending_expires_at' => CarbonImmutable::parse('2026-11-01T09:00:00Z')]);

        self::assertNull($this->router()->connectionFor('someone@example.com'));
        self::assertNull($this->router()->connectionFor('someone@expired.com'));
    }

    /**
     * A lapsed claim does not route.
     *
     * @return void
     */
    public function testALapsedClaimDoesNotRoute(): void
    {
        $this->makeDomain($this->connection, 'example.com', [
            'state'                    => DomainState::LAPSED,
            'last_successful_check_at' => CarbonImmutable::parse('2026-10-20T09:30:00Z'),
            'lapsed_at'                => CarbonImmutable::parse('2026-10-31T09:30:00Z'),
        ]);

        self::assertNull($this->router()->connectionFor('someone@example.com'));
    }

    /**
     * A claim no longer verified never routes, even if its `verified_domain`
     * were still set.
     *
     * @return void
     */
    public function testAClaimThatIsNotVerifiedNeverRoutes(): void
    {
        $this->makeDomain($this->connection, 'example.com', [
            'state'           => DomainState::LAPSED,
            'verified_domain' => 'example.com',
            'lapsed_at'       => CarbonImmutable::parse('2026-10-31T09:30:00Z'),
        ]);

        self::assertNull($this->router()->connectionFor('someone@example.com'));
    }

    /**
     * A domain another tenant holds verified routes to that tenant's
     * connection, whatever claims of it other tenants hold pending or lapsed.
     *
     * @return void
     */
    public function testAnotherTenantsVerifiedDomainRoutesToItsConnection(): void
    {
        $other  = $this->usableConnection(['tenant_id' => 'tenant-2']);
        $lapsed = $this->usableConnection(['tenant_id' => 'tenant-3']);

        $this->makeDomain($this->connection, 'shared.com');
        $this->makeDomain($lapsed, 'shared.com', ['state' => DomainState::LAPSED, 'lapsed_at' => CarbonImmutable::parse('2026-10-31T09:30:00Z')]);
        $this->makeDomain($other, 'shared.com', ['state' => DomainState::VERIFIED]);

        $routed = $this->router()->connectionFor('someone@shared.com');

        self::assertSame([$other->id, 'tenant-2'], [$routed?->id, $routed?->tenant_id]);
    }

    /**
     * A verified domain whose connection is disabled, incomplete or deleted
     * does not route.
     *
     * @return void
     */
    public function testAnUnusableConnectionDoesNotRoute(): void
    {
        $disabled   = $this->usableConnection(['enabled' => false]);
        $incomplete = $this->usableConnection(['settings' => []]);
        $deleted    = $this->usableConnection();

        $this->makeDomain($disabled, 'disabled.com', ['state' => DomainState::VERIFIED]);
        $this->makeDomain($incomplete, 'incomplete.com', ['state' => DomainState::VERIFIED]);
        $this->makeDomain($deleted, 'deleted.com', ['state' => DomainState::VERIFIED]);

        $deleted->delete();

        self::assertNull($this->router()->connectionFor('someone@disabled.com'));
        self::assertNull($this->router()->connectionFor('someone@incomplete.com'));
        self::assertNull($this->router()->connectionFor('someone@deleted.com'));
    }

    /**
     * A connection whose protocol is switched off does not route: the starting
     * driver is available only while a protocol is on.
     *
     * @return void
     */
    public function testAConnectionOfAProtocolSwitchedOffDoesNotRoute(): void
    {
        $this->makeDomain($this->connection, 'example.com', ['state' => DomainState::VERIFIED]);

        self::assertSame($this->connection->id, $this->router()->connectionFor('someone@example.com')?->id);

        config()->set('sso.features.oidc', false);

        self::assertNull($this->router()->connectionFor('someone@example.com'));
    }

    /**
     * Each email whose domain is an IDNA, upper-case or dotted form of the
     * claimed one.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function equivalentEmails(): iterable
    {
        yield 'Unicode' => ['someone@bücher.example.com'];
        yield 'Unicode in upper case' => ['Someone@BÜCHER.Example.COM'];
        yield 'ASCII in upper case' => ['someone@XN--BCHER-KVA.EXAMPLE.COM'];
        yield 'with a trailing dot' => ['someone@bücher.example.com.'];
        yield 'with surrounding space' => ['someone@ bücher.example.com '];
    }

    /**
     * An IDNA or upper-case domain is normalised before it is looked up.
     *
     * @param  string  $email
     * @return void
     */
    #[DataProvider('equivalentEmails')]
    public function testTheDomainIsNormalized(string $email): void
    {
        $this->makeDomain($this->connection, 'xn--bcher-kva.example.com', ['state' => DomainState::VERIFIED]);

        self::assertSame('xn--bcher-kva.example.com', DomainRouter::domainOf($email));
        self::assertSame($this->connection->id, $this->router()->connectionFor($email)?->id);
    }

    /**
     * A subdomain of a verified domain, and the domain it is under, do not
     * route: claims are exact.
     *
     * @return void
     */
    public function testASubdomainOfAVerifiedDomainDoesNotRoute(): void
    {
        $this->makeDomain($this->connection, 'mail.example.com', ['state' => DomainState::VERIFIED]);

        self::assertNull($this->router()->connectionFor('someone@sub.mail.example.com'));
        self::assertNull($this->router()->connectionFor('someone@example.com'));
        self::assertSame($this->connection->id, $this->router()->connectionFor('someone@mail.example.com')?->id);
    }

    /**
     * The domain is the part after the last `@`.
     *
     * @return void
     */
    public function testTheDomainIsAfterTheLastAt(): void
    {
        $this->makeDomain($this->connection, 'example.com', ['state' => DomainState::VERIFIED]);

        self::assertSame('example.com', DomainRouter::domainOf('someone@other.com@example.com'));
        self::assertSame('other.com', DomainRouter::domainOf('someone@example.com@other.com'));
        self::assertSame($this->connection->id, $this->router()->connectionFor('someone@other.com@example.com')?->id);
        self::assertNull($this->router()->connectionFor('someone@example.com@other.com'));
    }

    /**
     * Each email that has no domain to route, or one that does not normalise.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function emailsWithNoDomain(): iterable
    {
        yield 'empty' => [''];
        yield 'no @' => ['xexample.com'];
        yield 'the domain alone' => ['example.com'];
        yield 'nothing after the @' => ['someone@'];
        yield 'only spaces after the @' => ['someone@   '];
        yield 'an @ alone' => ['@'];
        yield 'a single label' => ['someone@com'];
        yield 'a special-use domain' => ['someone@localhost'];
        yield 'an IP address' => ['someone@[192.0.2.1]'];
        yield 'a wildcard' => ['someone@*.example.com'];
    }

    /**
     * An email with no domain, or a domain that does not normalise, is `null`,
     * never an exception, and reads nothing.
     *
     * @param  string  $email
     * @return void
     */
    #[DataProvider('emailsWithNoDomain')]
    public function testAnEmailWithNoDomainDoesNotRoute(string $email): void
    {
        $this->makeDomain($this->connection, 'example.com', ['state' => DomainState::VERIFIED]);

        $queries = $this->recordQueries();

        self::assertNull(DomainRouter::domainOf($email));
        self::assertNull($this->router()->connectionFor($email));
        self::assertSame([], $queries->getArrayCopy());
    }

    /**
     * An unknown domain does not route, after one read of the domains alone.
     *
     * @return void
     */
    public function testAnUnknownDomainDoesNotRoute(): void
    {
        $queries = $this->recordQueries();

        self::assertNull($this->router()->connectionFor('someone@unknown.com'));
        self::assertCount(1, $queries);
        self::assertStringContainsString('sso_domains', $queries[0]);
    }

    /**
     * Record the SQL of every statement run from now on.
     *
     * @return \ArrayObject<int, string>
     */
    private function recordQueries(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $queries */
        $queries = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($queries): void {
            $queries->append($query->sql);
        });

        return $queries;
    }

    /**
     * The router, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Discovery\DomainRouter
     */
    private function router(): DomainRouter
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(DomainRouter::class);
    }

    /**
     * An enabled connection over the starting driver, complete unless told
     * otherwise.
     *
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function usableConnection(array $attributes = []): Connection
    {
        return $this->makeConnection($attributes + [
            'protocol' => StartingDriver::NAME,
            'enabled'  => true,
            'settings' => ['issuer' => 'https://idp.example.com'],
        ]);
    }
}
