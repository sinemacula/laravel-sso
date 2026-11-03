<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Migrations\Migration;

/**
 * Creates and drops every table the package ships, through its migrations, on
 * the connection and under the name each is configured to, as an application
 * does when it publishes and runs them (SSO-11.7, SSO-11.10).
 *
 * A test calls `createEveryTable()` in its `setUp()` and `dropEveryTable()` in
 * its `tearDown()`, before the parent's, with the settings as they were when it
 * created them, so a persistent database starts the next test without them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait UsesEveryTable
{
    /**
     * Run every shipped migration.
     *
     * @return void
     */
    protected function createEveryTable(): void
    {
        foreach (self::everyMigration() as $migration) {
            $migration->up(); // @phpstan-ignore method.notFound
        }
    }

    /**
     * Roll every shipped migration back.
     *
     * @return void
     */
    protected function dropEveryTable(): void
    {
        foreach (array_reverse(self::everyMigration()) as $migration) {
            $migration->down(); // @phpstan-ignore method.notFound
        }
    }

    /**
     * Each shipped migration, in the order it runs.
     *
     * @return list<\Illuminate\Database\Migrations\Migration>
     */
    private static function everyMigration(): array
    {
        $files = glob(dirname(__DIR__, 2) . '/database/migrations/*.php') ?: [];

        sort($files);

        return array_map(static fn (string $file): Migration => require $file, $files);
    }
}
