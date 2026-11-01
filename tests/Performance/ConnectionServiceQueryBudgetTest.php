<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\ConnectionSummary;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use Tests\Fixtures\Freshness\RecordingFreshness;

/**
 * Query budgets for the management helpers. Each change runs in one
 * transaction, whose `BEGIN` and `COMMIT` are not statements a query sends:
 *
 * - `create()` reads nothing and writes once, the insert; refused, it sends
 *   nothing;
 * - `update()` reads once, the connection locked for update, and writes once,
 *   the update, when something changed; nothing changed, it writes nothing. A
 *   change to a subject setting (the issuer) also reads the connection's links
 *   with a locking read, and a trust change also voids the connection's
 *   requests and handoff codes in flight, one update each;
 * - `enable()` reads once and writes once, or writes nothing for an enabled
 *   connection;
 * - `get()` and `list()` read once, and write nothing.
 *
 * Masking the secrets and judging whether the connection is usable read nothing
 * more: the secrets are read from the row already loaded.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionService::class)]
final class ConnectionServiceQueryBudgetTest extends PerformanceContractTestCase
{
    /** @var string The tenant the connections belong to. */
    private const string TENANT = 'tenant-1';

    /** @var array<string, string> The settings of a complete OIDC connection, with its client secret. */
    private const array OIDC = [
        'issuer'                 => 'https://idp.example.com',
        'authorization_endpoint' => 'https://idp.example.com/authorize',
        'token_endpoint'         => 'https://idp.example.com/token',
        'jwks_uri'               => 'https://idp.example.com/jwks',
        'client_id'              => 'client-123',
        'client_secret'          => 'the-client-secret-value',
    ];

    /** @var \Tests\Fixtures\Freshness\RecordingFreshness The freshness contract the helpers ask. */
    private RecordingFreshness $freshness;

    /**
     * Turn OIDC on and bind a fresh freshness contract.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freshness = new RecordingFreshness;

        $this->app?->instance(Freshness::class, $this->freshness);

        config()->set('sso.features.oidc', true);
    }

    /**
     * A creation is one insert.
     *
     * @return void
     */
    public function testACreationIsOneInsert(): void
    {
        $result = $this->assertQueryBudget(0, 1, fn (): ConnectionResult => $this->create());

        self::assertSame(ConnectionStatus::CREATED, $result->status);
    }

    /**
     * A refused creation sends nothing.
     *
     * @return void
     */
    public function testARefusedCreationSendsNothing(): void
    {
        $this->freshness->answer(FreshnessOutcome::STALE);

        $result = $this->assertQueryBudget(0, 0, fn (): ConnectionResult => $this->create());

        self::assertTrue($result->isRefused());
    }

    /**
     * An update that changes the issuer is the locked read, the locking read of
     * the links, the update and the two voiding updates.
     *
     * @return void
     */
    public function testAnIssuerChangeIsTwoReadsAndThreeUpdates(): void
    {
        $id = $this->createdId();

        $result = $this->assertQueryBudget(2, 3, fn (): ConnectionResult => $this->service()->update(self::TENANT, $id, [
            'display_name' => 'Renamed',
            'settings'     => ['issuer' => 'https://login.example.com', 'client_secret' => 'a-new-client-secret'],
        ]));

        self::assertSame(ConnectionStatus::UPDATED, $result->status);
    }

    /**
     * An update that changes nothing is the locked read alone.
     *
     * @return void
     */
    public function testAnUnchangedUpdateIsOneRead(): void
    {
        $id = $this->createdId();

        $result = $this->assertQueryBudget(1, 0, fn (): ConnectionResult => $this->service()->update(self::TENANT, $id, ['display_name' => 'Acme']));

        self::assertSame(ConnectionStatus::UNCHANGED, $result->status);
    }

    /**
     * Enabling is the locked read and one update; enabling an enabled
     * connection is the read alone.
     *
     * @return void
     */
    public function testEnablingIsOneReadAndOneUpdate(): void
    {
        $id = $this->createdId();

        $enabled = $this->assertQueryBudget(1, 1, fn (): ConnectionResult => $this->service()->enable(self::TENANT, $id));
        $again   = $this->assertQueryBudget(1, 0, fn (): ConnectionResult => $this->service()->enable(self::TENANT, $id));

        self::assertSame(ConnectionStatus::ENABLED, $enabled->status);
        self::assertSame(ConnectionStatus::UNCHANGED, $again->status);
    }

    /**
     * Reading one connection is one read.
     *
     * @return void
     */
    public function testGettingIsOneRead(): void
    {
        $id = $this->createdId();

        $summary = $this->assertQueryBudget(1, 0, fn (): ?ConnectionSummary => $this->service()->get(self::TENANT, $id));

        self::assertSame($id, $summary?->id);
    }

    /**
     * Listing a tenant's connections is one read, however many there are.
     *
     * @return void
     */
    public function testListingIsOneRead(): void
    {
        $this->createdId();
        $this->createdId();
        $this->createdId();

        $listed = $this->assertQueryBudget(1, 0, fn (): array => $this->service()->list(self::TENANT));

        self::assertCount(3, $listed);
    }

    /**
     * Create the connection.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     */
    private function create(): ConnectionResult
    {
        return $this->service()->create(self::TENANT, 'oidc', 'Acme', self::OIDC);
    }

    /**
     * Create the connection, outside any budget, and return its id.
     *
     * @return string
     */
    private function createdId(): string
    {
        $result = $this->create();

        self::assertTrue($result->isSucceeded());

        return (string) $result->connection?->id;
    }

    /**
     * The management helpers, resolved per request.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionService
     */
    private function service(): ConnectionService
    {
        $service = $this->app?->make(ConnectionService::class);

        self::assertInstanceOf(ConnectionService::class, $service);

        return $service;
    }
}
