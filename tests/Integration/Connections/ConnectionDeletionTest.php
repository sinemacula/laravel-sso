<?php

declare(strict_types = 1);

namespace Tests\Integration\Connections;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Domains\Enums\DomainState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesDomains;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Integration tests that deleting a connection removes every row it owns and
 * none of another's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionLifecycle::class)]
final class ConnectionDeletionTest extends TestCase
{
    use UsesConnections, UsesDomains, UsesFlowTables;

    /** @var string The tenant the connections belong to. */
    private const string TENANT = 'tenant-1';

    /** @var array<string, string> Each table a connection owns rows in, by its configuration key under `sso.`. */
    private const array TABLES = [
        'domains'     => 'domains.table',
        'links'       => 'links.table',
        'keys'        => 'keys.table',
        'requests'    => 'authorization_requests.table',
        'codes'       => 'handoff_codes.table',
        'connections' => 'connections.table',
    ];

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /**
     * Bind a fixed clock and a fresh caller, and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock('2026-11-01T09:30:00Z');

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Freshness::class, FakeFreshness::fresh());

        $this->usePackageTables();
    }

    /**
     * Deleting a connection leaves no row of it and every other connection's
     * rows intact.
     *
     * @return void
     */
    public function testDeletesEveryRowOfTheConnectionAndNoneOfAnother(): void
    {
        $deleted = $this->populated('deleted');
        $before  = $this->populated('before');
        $after   = $this->populated('after');

        $result = $this->lifecycle()->delete(self::TENANT, $deleted->id, Clients::browser());

        self::assertSame(ConnectionStatus::DELETED, $result->status);
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        self::assertSame(['domains' => 0, 'links' => 0, 'keys' => 0, 'requests' => 0, 'codes' => 0, 'connections' => 0], self::countsOf($deleted->id));

        foreach ([$before, $after] as $kept) {
            self::assertSame(['domains' => 3, 'links' => 2, 'keys' => 4, 'requests' => 4, 'codes' => 3, 'connections' => 1], self::countsOf($kept->id));
        }
    }

    /**
     * Deleting the last connection empties every table.
     *
     * @return void
     */
    public function testDeletingTheLastConnectionEmptiesEveryTable(): void
    {
        $connection = $this->populated('only');

        self::assertTrue($this->lifecycle()->delete(self::TENANT, $connection->id, Clients::browser())->isChanged());

        foreach (self::TABLES as $key) {
            self::assertSame(0, DB::connection(StorageConnection::name())->table(StorageConnection::table($key))->count(), $key);
        }
    }

    /**
     * A connection with claims, links, keys, requests and codes in every state.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function populated(string $name): Connection
    {
        $connection = $this->makeConnection(['protocol' => 'saml2', 'enabled' => true]);
        $now        = $this->clock->now();

        $this->makeDomain($connection, "pending.{$name}.example.com");
        $this->makeDomain($connection, "verified.{$name}.example.com", ['state' => DomainState::VERIFIED]);
        $this->makeDomain($connection, "lapsed.{$name}.example.com", ['state' => DomainState::LAPSED, 'lapsed_at' => $now]);

        $this->makeLink($connection, "{$name}-active");
        $this->makeLink($connection, "{$name}-reserved", [
            'identity_id'            => '2',
            'state'                  => LinkState::RESERVED,
            'reservation_expires_at' => $now->addMinute(),
            'reservation_reference'  => str_repeat('r', 32),
        ]);

        $keys = [[KeyUse::SP_SIGNING, KeyState::CURRENT], [KeyUse::SP_SIGNING, KeyState::NEXT], [KeyUse::SP_ENCRYPTION, KeyState::RETIRING], [KeyUse::IDP_SIGNING, null]];

        foreach ($keys as $index => [$use, $state]) {
            $this->makeKey($connection, $use, $state, $index);
        }

        $this->makeAuthorizationRequest($connection);
        $this->makeAuthorizationRequest($connection, ['consumed_at' => $now]);
        $this->makeAuthorizationRequest($connection, ['consumed_at' => $now, 'completed_at' => $now]);
        $this->makeAuthorizationRequest($connection, ['voided_at' => $now]);

        $this->makeHandoffCode($connection);
        $this->makeHandoffCode($connection, ['redeemed_at' => $now]);
        $this->makeHandoffCode($connection, ['voided_at' => $now]);

        return $connection;
    }

    /**
     * Store a key of the connection of the use and state.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  ?\SineMacula\Laravel\Sso\Keys\Enums\KeyState  $state
     * @param  int  $index
     * @return void
     */
    private function makeKey(Connection $connection, KeyUse $use, ?KeyState $state, int $index): void
    {
        $key = new ConnectionKey;

        $key->forceFill([
            'connection_id' => $connection->id,
            'use'           => $use,
            'state'         => $state,
            'key_type'      => KeyType::EC,
            'key_bits'      => 256,
            'public_key'    => "the public key {$index} of {$connection->id}",
            'private_key'   => $state === null ? null : 'ciphertext',
            'fingerprint'   => hash('sha256', $connection->id . $index),
        ])->save();
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
     * How many rows the connection holds in each table, counted through the
     * query builder.
     *
     * @param  string  $connectionId
     * @return array<string, int>
     */
    private static function countsOf(string $connectionId): array
    {
        $database = DB::connection(StorageConnection::name());
        $counts   = [];

        foreach (self::TABLES as $name => $key) {
            $column        = $name === 'connections' ? 'id' : 'connection_id';
            $counts[$name] = $database->table(StorageConnection::table($key))->where($column, $connectionId)->count();
        }

        return $counts;
    }
}
