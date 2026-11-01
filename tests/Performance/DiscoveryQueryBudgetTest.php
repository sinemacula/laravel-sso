<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Discovery\DiscoveryService;
use SineMacula\Laravel\Sso\Discovery\DomainRouter;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\StartResult;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Fixtures\Protocols\StartingDriver;

/**
 * Query budgets for starting a flow by email domain (SSO-3.4, SSO-3.5,
 * SSO-11.3, SSO-11.8):
 *
 * - the attempt is counted against the IP address and the email's domain, an
 *   update and an insert for each new counter and one update for each after;
 * - a match then reads the domain's verified claim and its connection, and, in
 *   the transaction that stores the request, locks the connection again,
 *   inserts the request and raises the connection's flows version: three
 *   reads, an insert and an update;
 * - a miss reads the claim alone, and the connection too when the claim's
 *   connection is unusable; an email whose domain does not normalise reads
 *   nothing and counts the IP address alone;
 * - a refusal before routing reads nothing; a full IP counter stops at the
 *   limiter (its update, the insert its key refuses, the update again and one
 *   read); a full domain counter costs the same after the IP's slot, which is
 *   then given back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DiscoveryService::class)]
#[CoversClass(DomainRouter::class)]
final class DiscoveryQueryBudgetTest extends PerformanceContractTestCase
{
    use UsesConnections, UsesDomains;

    /**
     * Bind a request from an IP address, turn discovery on at its least floor,
     * register the applications and the driver, and make a usable connection
     * with its verified domain.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance('request', Request::create('/auth/sso/discovery', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7']));

        config()->set('sso.features.oidc', true);
        config()->set('sso.features.discovery', true);
        config()->set('sso.discovery.minimum_duration_milliseconds', 50);
        config()->set('sso.applications', [
            'web'         => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true],
            'discovering' => [
                'redirect_uri'     => 'https://app.example.com/sso',
                'external_sign_in' => true,
                'discovery'        => ['enabled' => true, 'fallback_url' => 'https://app.example.com/sign-in'],
            ],
        ]);

        $driver = new StartingDriver;

        app(ProtocolManager::class)->extend(StartingDriver::NAME, fn (): StartingDriver => $driver);

        $this->makeDomain($this->usableConnection(), 'example.com', ['state' => DomainState::VERIFIED]);
    }

    /**
     * The first match creates the IP address's and the domain's counters; a
     * later one updates them. Each reads the claim and the connection, locks
     * the connection again, inserts the request and raises the connection's
     * flows version.
     *
     * @return void
     */
    public function testAMatchIsItsAttemptThreeReadsAnInsertAndAnUpdate(): void
    {
        $first = $this->assertQueryBudget(3, 6, fn (): StartResult => $this->discover('someone@example.com'));
        $later = $this->assertQueryBudget(3, 4, fn (): StartResult => $this->discover('other@example.com'));

        self::assertSame(['https://idp.example.com/authorize?client_id=client-123', 'https://idp.example.com/authorize?client_id=client-123'], [
            $first->navigation?->jsonSerialize()['url'],
            $later->navigation?->jsonSerialize()['url'],
        ]);
        self::assertSame(2, AuthorizationRequest::query()->count());
    }

    /**
     * A miss reads the claim alone, or the claim and its unusable connection,
     * and writes nothing but its attempt; one whose domain does not normalise
     * reads nothing.
     *
     * @return void
     */
    public function testAMissReadsTheDomainAndWritesNoRequest(): void
    {
        $this->makeDomain($this->usableConnection(['enabled' => false]), 'disabled.com', ['state' => DomainState::VERIFIED]);

        $unknown    = $this->assertQueryBudget(1, 4, fn (): StartResult => $this->discover('someone@unknown.com'));
        $again      = $this->assertQueryBudget(1, 2, fn (): StartResult => $this->discover('someone@unknown.com'));
        $unusable   = $this->assertQueryBudget(2, 3, fn (): StartResult => $this->discover('someone@disabled.com'));
        $unroutable = $this->assertQueryBudget(0, 1, fn (): StartResult => $this->discover('someone@localhost'));

        foreach ([$unknown, $again, $unusable, $unroutable] as $result) {
            self::assertSame('https://app.example.com/sign-in', $result->navigation?->jsonSerialize()['url']);
        }

        self::assertSame(0, AuthorizationRequest::query()->count());
    }

    /**
     * A refusal before routing reads nothing; a full IP counter stops at the
     * limiter; a full domain counter after the IP's slot, which it gives back.
     *
     * @return void
     */
    public function testARefusedStartReadsNoDomain(): void
    {
        $this->discover('someone@unknown.com');

        $disabled = $this->assertQueryBudget(0, 2, fn (): StartResult => $this->discover('someone@unknown.com', 'web'));
        $missing  = $this->assertQueryBudget(0, 2, fn (): StartResult => $this->discover('someone@unknown.com', 'missing'));

        config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => 3, 'decay_seconds' => 60]);

        $ipLimited = $this->assertQueryBudget(1, 3, fn (): StartResult => $this->discover('someone@unknown.com'));

        config()->set('sso.rate_limits.authorization_request.per_ip', ['max' => 100, 'decay_seconds' => 60]);
        config()->set('sso.rate_limits.authorization_request.per_email_domain', ['max' => 3, 'decay_seconds' => 60]);

        $domainLimited = $this->assertQueryBudget(1, 5, fn (): StartResult => $this->discover('someone@unknown.com'));

        self::assertSame(FailureReason::FEATURE_DISABLED, $disabled->reason);
        self::assertSame(FailureReason::APPLICATION_NOT_ALLOWED, $missing->reason);
        self::assertTrue($ipLimited->isRateLimited());
        self::assertTrue($domainLimited->isRateLimited());
    }

    /**
     * Start a `sign_in` by the email for the application.
     *
     * @param  string  $email
     * @param  string  $application
     * @return \SineMacula\Laravel\Sso\Flows\StartResult
     */
    private function discover(string $email, string $application = 'discovering'): StartResult
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(DiscoveryService::class)->start($application, Purpose::SIGN_IN, $email);
    }

    /**
     * An enabled connection over the starting driver, complete.
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
