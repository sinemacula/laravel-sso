<?php

declare(strict_types = 1);

namespace Tests\Feature\Config\Checks;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Config\Checks\StorageCheck;
use Tests\Concerns\RunsConfigurationChecks;
use Tests\TestCase;

/**
 * Feature tests for the `[storage]` configuration check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StorageCheck::class)]
final class StorageCheckTest extends TestCase
{
    use RunsConfigurationChecks;

    /**
     * Storage is checked only while the package is in use.
     *
     * @return void
     */
    public function testAppliesOnlyWhileThePackageIsInUse(): void
    {
        config()->set('sso.storage.connection', 1);

        self::assertNull($this->problemsOf(StorageCheck::class));

        $this->useThePackage();
        config()->set('sso.storage.connection', null);

        self::assertSame([], $this->problemsOf(StorageCheck::class));
    }

    /**
     * Rows of `[settings, problems]`: storage configurations and their
     * problems.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: list<string>}>
     */
    public static function provideConfigurations(): iterable
    {
        yield 'configured connections' => [['sso.storage.connection' => 'testing', 'sso.rate_limits.connection' => 'testing'], []];
        yield 'renamed tables' => [['sso.single_use.table' => 'replay_keys', 'sso.rate_limits.table' => 'counters'], []];
        yield 'one name on two connections' => [
            [
                'database.connections.counters' => ['driver' => 'sqlite', 'database' => ':memory:'],
                'sso.rate_limits.connection'    => 'counters',
                'sso.rate_limits.table'         => 'sso_single_use_keys',
            ],
            [],
        ];
        yield 'an unconfigured storage connection' => [
            ['sso.storage.connection' => 'missing'],
            ['`sso.storage.connection` names the connection [missing], which is not configured in `database.connections`.'],
        ];
        yield 'an unconfigured storage connection the counters name too' => [
            ['sso.storage.connection' => 'missing', 'sso.rate_limits.connection' => 'missing'],
            [
                '`sso.storage.connection` names the connection [missing], which is not configured in `database.connections`.',
                '`sso.rate_limits.connection` names the connection [missing], which is not configured in `database.connections`.',
            ],
        ];
        yield 'an unconfigured counters connection' => [
            ['sso.rate_limits.connection' => 'missing'],
            ['`sso.rate_limits.connection` names the connection [missing], which is not configured in `database.connections`.'],
        ];
        yield 'an unconfigured counters connection beside an unconfigured storage connection' => [
            ['sso.storage.connection' => 'missing', 'sso.rate_limits.connection' => 'absent'],
            [
                '`sso.storage.connection` names the connection [missing], which is not configured in `database.connections`.',
                '`sso.rate_limits.connection` names the connection [absent], which is not configured in `database.connections`.',
            ],
        ];
        yield 'an empty counters connection on an unconfigured storage connection' => [
            ['sso.storage.connection' => 'missing', 'sso.rate_limits.connection' => ''],
            ['`sso.storage.connection` names the connection [missing], which is not configured in `database.connections`.'],
        ];
        yield 'a malformed connection' => [
            ['sso.rate_limits.connection' => ['counters']],
            ['`sso.rate_limits.connection` must be a connection name, or null or empty for the storage connection.'],
        ];
        yield 'a malformed table' => [
            ['sso.single_use.table' => 'sso keys'],
            ['`sso.single_use.table` must be a table name: letters, digits and underscores, not starting with a digit, optionally after a schema and a dot.'],
        ];
        yield 'one name for two tables' => [
            ['sso.rate_limits.table' => 'SSO_SINGLE_USE_KEYS'],
            ['`sso.single_use.table` and `sso.rate_limits.table` name the same table on the same connection.'],
        ];
    }

    /**
     * Each configuration reports exactly its problems.
     *
     * @param  array<string, mixed>  $settings
     * @param  list<string>  $problems
     * @return void
     */
    #[DataProvider('provideConfigurations')]
    public function testReportsEachProblem(array $settings, array $problems): void
    {
        $this->useThePackage();

        config()->set($settings);

        self::assertSame($problems, $this->problemsOf(StorageCheck::class));
    }
}
