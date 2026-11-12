<?php

declare(strict_types = 1);

namespace Tests\Feature\Connections;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\SubjectMigration;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\ConnectionDeleted;
use SineMacula\Laravel\Sso\Events\ConnectionDisabled;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\LinkCreated;
use SineMacula\Laravel\Sso\Events\LinkRemoved;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\RecordsEventSequences;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Event sequence tests for the connection lifecycle.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionLifecycle::class)]
#[CoversClass(SubjectMigration::class)]
#[CoversClass(ConnectionService::class)]
final class LifecycleEventSequenceTest extends TestCase
{
    use RecordsEventSequences, UsesFlowTables;

    /** @var string The tenant the connection belongs to. */
    private const string TENANT = 'tenant-1';

    /** @var list<string> Each refused change, or one that changes nothing, by name. */
    private const array REFUSALS = [
        'stale disable',
        'stale delete',
        'stale migration',
        'missing disable',
        'missing delete',
        'missing migration',
        'invalid migration',
        'colliding migration',
        'linked update',
        'repeated disable',
    ];

    /** @var array<string, string> The settings of a complete OIDC connection. */
    private const array OIDC = [
        'issuer'                 => 'https://idp.example.com',
        'authorization_endpoint' => 'https://idp.example.com/authorize',
        'token_endpoint'         => 'https://idp.example.com/token',
        'jwks_uri'               => 'https://idp.example.com/jwks',
        'client_id'              => 'client-123',
    ];

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFreshness The freshness contract the helpers ask. */
    private FakeFreshness $freshness;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The tenant's enabled OIDC connection. */
    private Connection $connection;

    /** @var list<\SineMacula\Laravel\Sso\Models\Link> The connection's links, oldest first. */
    private array $links = [];

    /**
     * Bind a fixed clock and a fresh caller, seed an OIDC connection with three
     * links, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freshness = FakeFreshness::fresh();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, $this->freshness);

        config()->set('sso.features.oidc', true);

        $this->usePackageTables();

        $created = $this->connections()->create(self::TENANT, 'oidc', 'Acme', Clients::browser(), self::OIDC);

        $this->connection = Connection::query()->whereKey((string) $created->connection?->id)->sole();
        $this->connection->forceFill(['enabled' => true])->save();

        foreach (['1', '2', '3'] as $identity) {
            $this->links[] = $this->makeLink($this->connection, 'subject-' . $identity, ['identity_id' => $identity]);
        }

        $this->startRecordingEvents();
    }

    /**
     * A disable reports `ConnectionDisabled` alone.
     *
     * @return void
     */
    public function testADisableReportsConnectionDisabled(): void
    {
        self::assertTrue($this->lifecycle()->disable(self::TENANT, $this->connection->id, Clients::browser())->isChanged());

        $this->assertEventSequence([ConnectionDisabled::class]);
    }

    /**
     * A deletion reports `ConnectionDeleted` alone, with no event per link.
     *
     * @return void
     */
    public function testADeletionReportsConnectionDeletedAlone(): void
    {
        self::assertTrue($this->lifecycle()->delete(self::TENANT, $this->connection->id, Clients::browser())->isChanged());

        self::assertSame(0, Link::query()->count());
        $this->assertEventSequence([ConnectionDeleted::class]);
    }

    /**
     * A migration reports the change, each removal in id order, then each new
     * link in relink order.
     *
     * @return void
     */
    public function testAMigrationReportsTheDocumentedSequence(): void
    {
        $this->migrate();

        $this->assertMigrationSequence();
    }

    /**
     * Inside a caller's transaction, a migration reports the same sequence on
     * commit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMigrationInsideACallersTransactionReportsOnCommit(): void
    {
        DB::connection(StorageConnection::name())->transaction(function (): void {

            $this->migrate();

            $this->assertNoEvents();
        });

        $this->assertMigrationSequence();
    }

    /**
     * Rows of `[change]`: each refusal of a lifecycle change.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusals(): iterable
    {
        foreach (self::REFUSALS as $change) {
            yield $change => [$change];
        }
    }

    /**
     * Every refusal, and a disable that changes nothing, reports nothing.
     *
     * @param  string  $change
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testARefusalReportsNothing(string $change): void
    {
        if (str_starts_with($change, 'stale')) {
            $this->freshness->staleFor(...FreshnessOperation::cases());
        }

        if ($change === 'repeated disable') {
            $this->connection->forceFill(['enabled' => false])->save();
        }

        $result = $this->refusals()[$change]();

        self::assertFalse($result->isChanged(), $change);
        $this->assertNoEvents();
    }

    /**
     * Each refused change, or one that changes nothing, by name.
     *
     * @return array<string, \Closure(): \SineMacula\Laravel\Sso\Connections\ConnectionResult>
     */
    private function refusals(): array
    {
        $id      = $this->connection->id;
        $unknown = '01jbunknownconnection00000';
        $first   = $this->links[0]->id;
        $second  = $this->links[1]->id;
        $all     = array_map(static fn (Link $link): string => $link->id, $this->links);
        $collide = [$first => ['x'], $second => ['x']];

        return [
            'stale disable'   => fn (): ConnectionResult => $this->lifecycle()->disable(self::TENANT, $id, Clients::browser()),
            'stale delete'    => fn (): ConnectionResult => $this->lifecycle()->delete(self::TENANT, $id, Clients::browser()),
            'stale migration' => fn (): ConnectionResult => $this->migration()->migrate(
                self::TENANT,
                $id,
                ['settings' => ['client_id' => 'client-456']],
                [],
                $all,
                Clients::browser(),
            ),
            'missing disable'     => fn (): ConnectionResult => $this->lifecycle()->disable(self::TENANT, $unknown, Clients::browser()),
            'missing delete'      => fn (): ConnectionResult => $this->lifecycle()->delete(self::TENANT, $unknown, Clients::browser()),
            'missing migration'   => fn (): ConnectionResult => $this->migration()->migrate(self::TENANT, $unknown, ['display_name' => 'Renamed'], [], $all, Clients::browser()),
            'invalid migration'   => fn (): ConnectionResult => $this->migration()->migrate(self::TENANT, $id, ['display_name' => ''], [], $all, Clients::browser()),
            'colliding migration' => fn (): ConnectionResult => $this->migration()->migrate(
                self::TENANT,
                $id,
                ['display_name' => 'Renamed'],
                $collide,
                [$this->links[2]->id],
                Clients::browser(),
            ),
            'linked update'    => fn (): ConnectionResult => $this->connections()->update(self::TENANT, $id, ['settings' => ['client_id' => 'client-456']], Clients::browser()),
            'repeated disable' => fn (): ConnectionResult => $this->lifecycle()->disable(self::TENANT, $id, Clients::browser()),
        ];
    }

    /**
     * Migrate to a new client id, relinking the third and first links and
     * removing the second.
     *
     * @return void
     */
    private function migrate(): void
    {
        $result = $this->migration()->migrate(self::TENANT, $this->connection->id, ['settings' => ['client_id' => 'client-456']], [
            $this->links[2]->id => ['subject-3-new'],
            $this->links[0]->id => ['subject-1-new'],
        ], [$this->links[1]->id], Clients::browser());

        self::assertTrue($result->isChanged());
    }

    /**
     * Assert the change, three removals in id order, then the third and first
     * identities relinked.
     *
     * @return void
     */
    private function assertMigrationSequence(): void
    {
        $this->assertEventSequence([ConnectionUpdated::class, LinkRemoved::class, LinkRemoved::class, LinkRemoved::class, LinkCreated::class, LinkCreated::class]);

        $identities = array_map(static fn (SsoEvent $event): ?string => $event->context()->identityId, $this->recordedEvents());

        self::assertSame([null, '1', '2', '3', '3', '1'], $identities);
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
     * The subject migration helper, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Connections\SubjectMigration
     */
    private function migration(): SubjectMigration
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(SubjectMigration::class);
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
