<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Connections\InFlightVoider;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use Tests\Fixtures\Freshness\RecordingFreshness;

/**
 * Deterministic query budgets of the connection lifecycle and the voiding a
 * trust change makes, however many rows each touches:
 *
 * - `disable()`: 2 reads (the connection, then again locked) and 4 writes (the
 *   connection, its unfinished requests, its unredeemed codes, its trust
 *   version); a disabled connection, the 2 reads alone;
 * - `delete()`: 3 reads (the connection, then again locked, then its domain
 *   claims locked) and 9 writes (the requests and codes voided and the trust
 *   version raised; the domains, requests, codes, links and keys deleted; then
 *   the connection);
 * - `update()` with a trust change: the locked read and 4 writes (the
 *   connection, its requests, its codes, its trust version); a change to a
 *   subject setting adds the locking read of its links, and refused for a link
 *   it writes nothing; a change that asks no trust is the read and one write.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionLifecycle::class)]
#[CoversClass(ConnectionService::class)]
#[CoversClass(InFlightVoider::class)]
final class ConnectionLifecycleQueryBudgetTest extends PerformanceContractTestCase
{
    /** @var string The tenant the connection belongs to. */
    private const string TENANT = 'tenant-1';

    /** @var int Requests and codes the connection has in flight, which the budgets do not grow with. */
    private const int IN_FLIGHT = 5;

    /** @var array<string, string> The settings of a complete OIDC connection. */
    private const array OIDC = [
        'issuer'                 => 'https://idp.example.com',
        'authorization_endpoint' => 'https://idp.example.com/authorize',
        'token_endpoint'         => 'https://idp.example.com/token',
        'jwks_uri'               => 'https://idp.example.com/jwks',
        'client_id'              => 'client-123',
    ];

    /** @var \SineMacula\Laravel\Sso\Models\Connection The tenant's enabled connection, with requests and codes in flight. */
    private Connection $connection;

    /**
     * Turn OIDC on, bind a fresh freshness contract, and create an enabled
     * connection with requests and codes in flight, outside any budget.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Freshness::class, new RecordingFreshness);

        config()->set('sso.features.oidc', true);

        $created = $this->connections()->create(self::TENANT, 'oidc', 'Acme', self::OIDC);

        $this->connection = Connection::query()->whereKey((string) $created->connection?->id)->sole();
        $this->connection->forceFill(['enabled' => true])->save();

        for ($index = 0; $index < self::IN_FLIGHT; $index++) {
            $this->inFlight();
        }
    }

    /**
     * Disabling is two reads and four writes, however much is in flight; a
     * disabled connection is the two reads alone.
     *
     * @return void
     */
    public function testDisablingIsTwoReadsAndFourWrites(): void
    {
        $disabled = $this->assertQueryBudget(2, 4, fn (): ConnectionResult => $this->lifecycle()->disable(self::TENANT, $this->connection->id));
        $again    = $this->assertQueryBudget(2, 0, fn (): ConnectionResult => $this->lifecycle()->disable(self::TENANT, $this->connection->id));

        self::assertSame(ConnectionStatus::DISABLED, $disabled->status);
        self::assertSame(ConnectionStatus::UNCHANGED, $again->status);
        self::assertSame(self::IN_FLIGHT, AuthorizationRequest::query()->whereNotNull('voided_at')->count());
        self::assertSame(self::IN_FLIGHT, HandoffCode::query()->whereNotNull('voided_at')->count());
    }

    /**
     * Deleting is three reads and nine writes, however many rows go.
     *
     * @return void
     */
    public function testDeletingIsThreeReadsAndNineWrites(): void
    {
        $this->makeLinks();

        $result = $this->assertQueryBudget(3, 9, fn (): ConnectionResult => $this->lifecycle()->delete(self::TENANT, $this->connection->id));

        self::assertSame(ConnectionStatus::DELETED, $result->status);
        self::assertSame(0, Link::query()->count());
        self::assertSame(0, AuthorizationRequest::query()->count());
    }

    /**
     * A trust change that alters no subject is the locked read and four writes.
     *
     * @return void
     */
    public function testATrustChangeIsOneReadAndFourWrites(): void
    {
        $result = $this->assertQueryBudget(1, 4, fn (): ConnectionResult => $this->updateSettings(['token_endpoint' => 'https://idp.example.com/oauth2/token']));

        self::assertSame(ConnectionStatus::UPDATED, $result->status);
        self::assertSame(0, HandoffCode::query()->whereNull('voided_at')->count());
    }

    /**
     * A change to a subject setting adds the locking read of the links; with a
     * link, it is refused and writes nothing.
     *
     * @return void
     */
    public function testASubjectChangeAddsTheReadOfTheLinks(): void
    {
        $updated = $this->assertQueryBudget(2, 4, fn (): ConnectionResult => $this->updateSettings(['client_id' => 'client-456']));

        $this->makeLinks();

        $refused = $this->assertQueryBudget(2, 0, fn (): ConnectionResult => $this->updateSettings(['client_id' => 'client-789']));

        self::assertSame(ConnectionStatus::UPDATED, $updated->status);
        self::assertSame(FailureReason::CONNECTION_HAS_LINKS, $refused->reason);
    }

    /**
     * A change that asks no trust voids nothing: the read and one write.
     *
     * @return void
     */
    public function testAChangeThatAsksNoTrustIsOneReadAndOneWrite(): void
    {
        $result = $this->assertQueryBudget(1, 1, fn (): ConnectionResult => $this->updateSettings(['scopes' => ['openid']]));

        self::assertSame(ConnectionStatus::UPDATED, $result->status);
        self::assertSame(self::IN_FLIGHT, HandoffCode::query()->whereNull('voided_at')->count());
    }

    /**
     * Update the connection's settings.
     *
     * @param  array<string, mixed>  $settings
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     */
    private function updateSettings(array $settings): ConnectionResult
    {
        return $this->connections()->update(self::TENANT, $this->connection->id, ['settings' => $settings]);
    }

    /**
     * Store a request and a code in flight through the connection.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    private function inFlight(): void
    {
        $now     = $this->clock->now();
        $request = new AuthorizationRequest;

        $request->forceFill([
            'reference'         => rtrim(strtr(base64_encode(random_bytes(24)), '+/', '-_'), '='),
            'state_digest'      => hash('sha256', random_bytes(24)),
            'purpose'           => 'sign_in',
            'application'       => 'web',
            'connection_id'     => $this->connection->id,
            'handoff_challenge' => str_repeat('c', 43),
            'expires_at'        => $now->addMinutes(10),
        ])->save();

        $code = new HandoffCode;

        $code->forceFill([
            'code_digest'       => hash('sha256', random_bytes(32)),
            'purpose'           => 'sign_in',
            'application'       => 'web',
            'connection_id'     => $this->connection->id,
            'request_reference' => $request->reference,
            'handoff_challenge' => str_repeat('c', 43),
            'result'            => '',
            'expires_at'        => $now->addMinute(),
        ])->save();
    }

    /**
     * Link three subjects through the connection.
     *
     * @return void
     */
    private function makeLinks(): void
    {
        foreach (['1', '2', '3'] as $identity) {

            $link = new Link;

            $link->forceFill([
                'connection_id' => $this->connection->id,
                'issuer'        => 'https://idp.example.com',
                'subject'       => 'subject-' . $identity,
                'subject_key'   => hash('sha256', 'subject-' . $identity),
                'identity_type' => 'user',
                'identity_id'   => $identity,
            ])->save();
        }
    }

    /**
     * The disable and delete helpers, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionLifecycle
     */
    private function lifecycle(): ConnectionLifecycle
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(ConnectionLifecycle::class);
    }

    /**
     * The management helpers, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionService
     */
    private function connections(): ConnectionService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(ConnectionService::class);
    }
}
