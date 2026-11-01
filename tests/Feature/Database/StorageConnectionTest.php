<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use Tests\TestCase;

/**
 * Feature tests for where the package's tables live and what they are called:
 * the storage connection, the counters' connection that falls back to it, the
 * connection and name of each table, a malformed setting failing closed,
 * whether a model lives on the storage connection, compared by name, and an
 * operation refused while a transaction is open on it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StorageConnection::class)]
final class StorageConnectionTest extends TestCase
{
    /**
     * The storage connection is the one configured, read on each call; `null`
     * or an empty name means the default connection.
     *
     * @return void
     */
    public function testTheStorageConnectionIsTheConfiguredOne(): void
    {
        self::assertNull(StorageConnection::name());
        self::assertSame('testing', StorageConnection::resolvedName());

        config()->set('sso.storage.connection', 'package_store');

        self::assertSame('package_store', StorageConnection::name());
        self::assertSame('package_store', StorageConnection::resolvedName());

        config()->set('sso.storage.connection', '');

        self::assertNull(StorageConnection::name());
        self::assertSame('testing', StorageConnection::resolvedName());
    }

    /**
     * The counters live on the connection `rate_limits.connection` names, and
     * on the storage connection when it names none; every other table on the
     * storage connection.
     *
     * @return void
     */
    public function testTheCountersFallBackToTheStorageConnection(): void
    {
        self::assertNull(StorageConnection::forRateLimits());

        config()->set('sso.storage.connection', 'package_store');

        self::assertSame('package_store', StorageConnection::forRateLimits());
        self::assertSame('package_store', StorageConnection::connectionFor('rate_limits.table'));

        config()->set('sso.rate_limits.connection', 'counters');

        self::assertSame('counters', StorageConnection::forRateLimits());
        self::assertSame('counters', StorageConnection::connectionFor('rate_limits.table'));
        self::assertSame('package_store', StorageConnection::connectionFor('single_use.table'));

        config()->set('sso.rate_limits.connection', '');

        self::assertSame('package_store', StorageConnection::forRateLimits());
    }

    /**
     * Rows of `[key, value, message]`: settings that are neither a connection
     * name nor `null` or empty, and what each is refused with.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function provideMalformedConnections(): iterable
    {
        $storage = '`sso.storage.connection` must be a connection name, or null or empty for the default connection.';
        $limits  = '`sso.rate_limits.connection` must be a connection name, or null or empty for the storage connection.';

        yield from [
            'a storage list of names'     => ['storage.connection', ['package_store'], $storage],
            'a storage true'              => ['storage.connection', true, $storage],
            'a storage false'             => ['storage.connection', false, $storage],
            'a storage integer'           => ['storage.connection', 1, $storage],
            'a rate limits list of names' => ['rate_limits.connection', ['counters'], $limits],
            'a rate limits integer'       => ['rate_limits.connection', 0, $limits],
        ];
    }

    /**
     * A setting that is not a name fails closed, naming the key, instead of
     * putting the tables on another connection than the one meant; the
     * counters' connection refuses a malformed storage connection too.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedConnections')]
    public function testRefusesAConnectionThatIsNotAName(string $key, mixed $value, string $message): void
    {
        config()->set('sso.' . $key, $value);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        StorageConnection::connectionFor('rate_limits.table');
    }

    /**
     * Each table takes its default name, with the `sso_` prefix, until its
     * setting names another, and every table the package has is listed.
     *
     * @return void
     */
    public function testEachTableTakesItsConfiguredName(): void
    {
        self::assertSame([
            'single_use.table'             => 'sso_single_use_keys',
            'rate_limits.table'            => 'sso_rate_limits',
            'connections.table'            => 'sso_connections',
            'keys.table'                   => 'sso_keys',
            'domains.table'                => 'sso_domains',
            'enforcement.table'            => 'sso_enforcement',
            'links.table'                  => 'sso_links',
            'authorization_requests.table' => 'sso_authorization_requests',
            'handoff_codes.table'          => 'sso_handoff_codes',
        ], StorageConnection::TABLES);

        foreach (StorageConnection::TABLES as $key => $default) {
            self::assertStringStartsWith('sso_', $default);
            self::assertSame($default, StorageConnection::table($key));
        }

        config()->set('sso.single_use.table', 'replay_keys');
        config()->set('sso.rate_limits.table', 'auth.counters');

        self::assertSame('replay_keys', StorageConnection::table('single_use.table'));
        self::assertSame('auth.counters', StorageConnection::table('rate_limits.table'));

        config()->set('sso.single_use', []);

        self::assertSame('sso_single_use_keys', StorageConnection::table('single_use.table'));
    }

    /**
     * Rows of `[value]`: table names refused.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedTables(): iterable
    {
        yield from [
            'null'               => [null],
            'empty'              => [''],
            'an integer'         => [1],
            'a leading digit'    => ['1keys'],
            'a space'            => ['sso keys'],
            'a quote'            => ['sso_keys"'],
            'a dash'             => ['sso-keys'],
            'two dots'           => ['a.b.c'],
            'a trailing dot'     => ['sso_keys.'],
            'sixty-four letters' => [str_repeat('a', 64)],
        ];
    }

    /**
     * A table name that is not a plain, optionally schema-qualified, name fails
     * closed, naming the key.
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMalformedTables')]
    public function testRefusesATableThatIsNotAName(mixed $value): void
    {
        config()->set('sso.single_use.table', $value);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`sso.single_use.table` must be a table name');

        StorageConnection::table('single_use.table');
    }

    /**
     * A key that names no package table is a caller's mistake, whether its
     * table or its connection is asked for.
     *
     * @return void
     */
    public function testRefusesAKeyThatNamesNoTable(): void
    {
        foreach ([StorageConnection::table(...), StorageConnection::connectionFor(...)] as $read) {
            try {
                $read('tokens.table');

                self::fail('Expected the key to be refused.');
            } catch (\LogicException $exception) {
                $known = '`sso.single_use.table`, `sso.rate_limits.table`, `sso.connections.table`, `sso.keys.table`, `sso.domains.table`, `sso.enforcement.table`, '
                    . '`sso.links.table`, `sso.authorization_requests.table`, `sso.handoff_codes.table`';

                self::assertSame("`sso.tokens.table` names no package table; the tables are named by {$known}.", $exception->getMessage());
            }
        }
    }

    /**
     * A model lives on the storage connection when the two name the same one, a
     * model that names none counting as on the default.
     *
     * @return void
     */
    public function testAModelOnTheStorageConnectionIsHeld(): void
    {
        $default  = new class extends Model {};
        $separate = (new class extends Model {})->setConnection('package_store');

        self::assertTrue(StorageConnection::holds($default));
        self::assertSame('testing', StorageConnection::nameOf($default));
        self::assertFalse(StorageConnection::holds($separate));
        self::assertSame('package_store', StorageConnection::nameOf($separate));

        config()->set('sso.storage.connection', 'package_store');

        self::assertFalse(StorageConnection::holds($default));
        self::assertTrue(StorageConnection::holds($separate));
    }

    /**
     * An operation that runs outside any transaction is refused, with the
     * message given, while one is open on the storage connection, however deep,
     * and is let through once none is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesAnOperationInsideATransaction(): void
    {
        $database = DB::connection(StorageConnection::name());
        $refusals = [];

        StorageConnection::assertNoTransaction('Never refused.');

        $database->beginTransaction();

        foreach ([1, 2] as $level) {

            try {
                StorageConnection::assertNoTransaction("Refused at level {$level}.");
            } catch (\LogicException $exception) {
                $refusals[] = $exception->getMessage();
            }

            $database->beginTransaction();
        }

        $database->rollBack();
        $database->rollBack();
        $database->rollBack();

        StorageConnection::assertNoTransaction('Never refused.');

        self::assertSame(['Refused at level 1.', 'Refused at level 2.'], $refusals);
        self::assertSame(0, $database->transactionLevel());
    }

    /**
     * `StorageConnection` is a utility container, not to be instantiated.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(StorageConnection::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(StorageConnection::class, $instance);
    }
}
