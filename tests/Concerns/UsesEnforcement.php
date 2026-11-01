<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Str;
use SineMacula\Laravel\Sso\Models\TenantEnforcement;

/**
 * Creates and drops the enforcement table through its shipped migration, on the
 * storage connection and under its configured name, and makes a tenant's
 * enforcement for a test to work on.
 *
 * A test calls `createEnforcementTable()` in its `setUp()` and
 * `dropEnforcementTable()` in its `tearDown()`, before the parent's, so a
 * persistent database starts the next test without it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait UsesEnforcement
{
    /**
     * Run the enforcement table's shipped migration.
     *
     * @return void
     */
    protected function createEnforcementTable(): void
    {
        self::enforcementMigration()->up(); // @phpstan-ignore method.notFound
    }

    /**
     * Roll the enforcement table's shipped migration back.
     *
     * @return void
     */
    protected function dropEnforcementTable(): void
    {
        self::enforcementMigration()->down(); // @phpstan-ignore method.notFound
    }

    /**
     * Make and save a tenant's enforcement: `tenant-1`'s, off, with no
     * satisfying connection, a new version and changed at the claim fixture's
     * time, unless the attributes given say otherwise.
     *
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\TenantEnforcement
     */
    protected function makeEnforcement(array $attributes = []): TenantEnforcement
    {
        $enforcement = new TenantEnforcement;

        $enforcement->forceFill($attributes + [
            'tenant_id'      => 'tenant-1',
            'enabled'        => false,
            'connection_ids' => [],
            'version'        => strtolower((string) Str::ulid()),
            'changed_at'     => CarbonImmutable::parse('2026-11-01T09:30:00Z'),
        ])->save();

        return $enforcement;
    }

    /**
     * The shipped migration of the enforcement table.
     *
     * @return \Illuminate\Database\Migrations\Migration
     */
    private static function enforcementMigration(): Migration
    {
        return require dirname(__DIR__, 2) . '/database/migrations/2026_11_02_000001_create_sso_enforcement_table.php';
    }
}
