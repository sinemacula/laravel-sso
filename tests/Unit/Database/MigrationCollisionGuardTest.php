<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Database\Connection;
use Illuminate\Database\Schema\Builder;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Sso\Database\TableAlreadyExistsException;

/**
 * MigrationCollisionGuard unit tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MigrationCollisionGuard::class)]
final class MigrationCollisionGuardTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * The guard throws naming the table, the connection and the config key.
     *
     * @return void
     */
    public function testEnsureNotExistsThrowsWhenTableExists(): void
    {
        $schema = \Mockery::mock(Builder::class);
        $schema->shouldReceive('hasTable')
            ->once()
            ->with('sso_single_use_keys')
            ->andReturn(true);

        $connection = \Mockery::mock(Connection::class);
        $connection->shouldReceive('getName')
            ->once()
            ->andReturn('testing');

        $schema->shouldReceive('getConnection')
            ->once()
            ->andReturn($connection);

        $guard = new MigrationCollisionGuard($schema);

        $this->expectException(TableAlreadyExistsException::class);
        $this->expectExceptionMessage(
            'Cannot install the laravel-sso migration for the \'sso_single_use_keys\' table: a table with that name already exists on connection \'testing\'.'
            . ' Set `single_use.table` in config/sso.php to a different name and re-run the migration.',
        );

        $guard->ensureNotExists('sso_single_use_keys', 'single_use.table');
    }

    /**
     * The guard returns silently when the table is missing.
     *
     * @return void
     */
    public function testEnsureNotExistsSucceedsWhenTableMissing(): void
    {
        $schema = \Mockery::mock(Builder::class);
        $schema->shouldReceive('hasTable')
            ->once()
            ->with('sso_single_use_keys')
            ->andReturn(false);

        $guard = new MigrationCollisionGuard($schema);

        // The `->once()` expectation on hasTable is the assertion.
        $guard->ensureNotExists('sso_single_use_keys', 'single_use.table');
    }

    /**
     * The message names the given table and key, and an unnamed connection.
     *
     * @return void
     */
    public function testEnsureNotExistsNamesTheGivenTableAndKey(): void
    {
        $schema = \Mockery::mock(Builder::class);
        $schema->shouldReceive('hasTable')
            ->once()
            ->with('sso_attempt_counters')
            ->andReturn(true);

        $connection = \Mockery::mock(Connection::class);
        $connection->shouldReceive('getName')
            ->andReturnNull();

        $schema->shouldReceive('getConnection')
            ->andReturn($connection);

        $guard = new MigrationCollisionGuard($schema);

        $this->expectException(TableAlreadyExistsException::class);
        $this->expectExceptionMessage('the \'sso_attempt_counters\' table: a table with that name already exists on connection \'default\'. Set `rate_limits.table`');

        $guard->ensureNotExists('sso_attempt_counters', 'rate_limits.table');
    }
}
