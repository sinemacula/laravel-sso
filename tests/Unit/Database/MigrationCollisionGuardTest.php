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
     * Asserts the guard throws when the table already exists in the schema,
     * naming the table, the connection and the configuration key that renames
     * the table.
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
     * Asserts the guard returns silently when the table is not present in the
     * schema.
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

        // ensureNotExists is `void` and the assertion lives in the Mockery
        // `->once()` expectation: if hasTable was not called exactly once,
        // Mockery will fail the test in tearDown.
        $guard->ensureNotExists('sso_single_use_keys', 'single_use.table');
    }

    /**
     * Asserts the exception message echoes the table name and configuration key
     * supplied at runtime, and names the default connection when the connection
     * has no name.
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
