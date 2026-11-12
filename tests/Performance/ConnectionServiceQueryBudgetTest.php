<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\ConnectionSummary;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Connections\ImportSaver;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOutcome;
use SineMacula\Laravel\Sso\Metadata\ValidatedFetch;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Freshness\RecordingFreshness;

/**
 * Query budgets for the management helpers. Masking secrets and judging
 * usability read nothing more.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionService::class)]
#[CoversClass(ImportSaver::class)]
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
     * Turn OIDC on and answer `fresh` to every freshness check.
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
     * The locked read and the links' locking read, the update and the voiding's
     * four writes: requests, codes, trust version and reservations.
     *
     * @return void
     */
    public function testAnIssuerChangeIsTwoReadsAndFiveWrites(): void
    {
        $id = $this->createdId();

        $result = $this->assertQueryBudget(2, 5, fn (): ConnectionResult => $this->service()->update(self::TENANT, $id, [
            'display_name' => 'Renamed',
            'settings'     => ['issuer' => 'https://login.example.com', 'client_secret' => 'a-new-client-secret'],
        ], Clients::browser()));

        self::assertSame(ConnectionStatus::UPDATED, $result->status);
    }

    /**
     * The locked read and the keys' locking read, the update and the voiding's
     * four writes.
     *
     * @return void
     */
    public function testAClientAssertionAlgorithmChangeIsTwoReadsAndFiveWrites(): void
    {
        $id = $this->createdId();

        $result = $this->assertQueryBudget(
            2,
            5,
            fn (): ConnectionResult => $this->service()->update(self::TENANT, $id, ['settings' => ['client_assertion_algorithm' => 'RS256']], Clients::browser()),
        );

        self::assertSame(ConnectionStatus::UPDATED, $result->status);
    }

    /**
     * A fetched import changing a setting that asks no freshness is the locked
     * read, the update and the fetch stamp.
     *
     * @return void
     */
    public function testAnImportSaveIsOneReadAndTwoUpdates(): void
    {
        $id = $this->createdId();

        $result = $this->assertQueryBudget(1, 2, fn (): ConnectionResult => $this->saveImport($id, 'Renamed'));

        self::assertSame(ConnectionStatus::UPDATED, $result->status);
    }

    /**
     * An unchanged fetched import is the locked read and the fetch stamp.
     *
     * @return void
     */
    public function testAnUnchangedImportSaveIsOneReadAndOneUpdate(): void
    {
        $id = $this->createdId();

        $result = $this->assertQueryBudget(1, 1, fn (): ConnectionResult => $this->saveImport($id, 'Acme'));

        self::assertSame(ConnectionStatus::UNCHANGED, $result->status);
    }

    /**
     * A stale caller's import save is the locked read alone.
     *
     * @return void
     */
    public function testAStaleImportSaveIsOneRead(): void
    {
        $id = $this->createdId();

        $this->freshness->answer(FreshnessOutcome::STALE);

        $result = $this->assertQueryBudget(1, 0, fn (): ConnectionResult => $this->saveImport($id, 'Renamed'));

        self::assertTrue($result->isRefused());
    }

    /**
     * An update that changes nothing is the locked read alone.
     *
     * @return void
     */
    public function testAnUnchangedUpdateIsOneRead(): void
    {
        $id = $this->createdId();

        $result = $this->assertQueryBudget(1, 0, fn (): ConnectionResult => $this->service()->update(self::TENANT, $id, ['display_name' => 'Acme'], Clients::browser()));

        self::assertSame(ConnectionStatus::UNCHANGED, $result->status);
    }

    /**
     * The locked read and one update; for an enabled connection, the read
     * alone.
     *
     * @return void
     */
    public function testEnablingIsOneReadAndOneUpdate(): void
    {
        $id = $this->createdId();

        $enabled = $this->assertQueryBudget(1, 1, fn (): ConnectionResult => $this->service()->enable(self::TENANT, $id, Clients::browser()));
        $again   = $this->assertQueryBudget(1, 0, fn (): ConnectionResult => $this->service()->enable(self::TENANT, $id, Clients::browser()));

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
     * One read, however many connections the tenant has.
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
        return $this->service()->create(self::TENANT, 'oidc', 'Acme', Clients::browser(), self::OIDC);
    }

    /**
     * Create the connection outside any budget and return its id.
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
     * Save a fetched import with the display name given.
     *
     * @param  string  $id
     * @param  string  $name
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     */
    private function saveImport(string $id, string $name): ConnectionResult
    {
        return app(ImportSaver::class)->save(self::TENANT, $id, ['display_name' => $name], new ValidatedFetch($this->clock->now()), Clients::browser());
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
