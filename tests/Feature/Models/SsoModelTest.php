<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Models\SsoModel;
use Tests\Fixtures\Models\ExampleCounter;
use Tests\Fixtures\Models\ExampleKey;
use Tests\Fixtures\Models\UntabledModel;
use Tests\TestCase;

/**
 * Feature tests for the base of every package model: it takes its configured
 * table and the connection that table lives on when it is built, and fails
 * closed on a malformed setting or a model that names no table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SsoModel::class)]
final class SsoModelTest extends TestCase
{
    /**
     * A model takes its table's default name and the default connection until
     * the settings name others, read each time a model is built.
     *
     * @return void
     */
    public function testTakesItsTableAndConnectionWhenBuilt(): void
    {
        $key = new ExampleKey(['namespace' => 'example']);

        self::assertSame('sso_single_use_keys', $key->getTable());
        self::assertNull($key->getConnectionName());
        self::assertSame('example', $key->namespace);

        config()->set('sso.single_use.table', 'replay_keys');
        config()->set('sso.storage.connection', 'package_store');

        $moved = new ExampleKey;

        self::assertSame('replay_keys', $moved->getTable());
        self::assertSame('package_store', $moved->getConnectionName());
        self::assertSame('sso_single_use_keys', $key->getTable());
    }

    /**
     * The rate limits table's model lives on the counters' connection, and on
     * the storage connection when that names none.
     *
     * @return void
     */
    public function testTheCountersModelTakesTheCountersConnection(): void
    {
        config()->set('sso.storage.connection', 'package_store');

        self::assertSame('package_store', (new ExampleCounter)->getConnectionName());
        self::assertSame('sso_rate_limits', (new ExampleCounter)->getTable());

        config()->set('sso.rate_limits.connection', 'counters');

        self::assertSame('counters', (new ExampleCounter)->getConnectionName());
        self::assertSame('package_store', (new ExampleKey)->getConnectionName());
    }

    /**
     * A malformed table name or connection fails when the model is built, never
     * reading or writing another table or connection than the one meant.
     *
     * @return void
     */
    public function testAMalformedSettingFailsWhenBuilt(): void
    {
        config()->set('sso.single_use.table', 'sso keys');

        try {
            new ExampleKey;

            self::fail('Expected the table to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringStartsWith('`sso.single_use.table` must be a table name', $exception->getMessage());
        }

        config()->set('sso.single_use.table', 'sso_single_use_keys');
        config()->set('sso.storage.connection', ['package_store']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`sso.storage.connection` must be a connection name');

        new ExampleKey;
    }

    /**
     * A model that names no table fails when it is built.
     *
     * @return void
     */
    public function testAModelThatNamesNoTableFails(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('`sso.` names no package table');

        new UntabledModel;
    }
}
