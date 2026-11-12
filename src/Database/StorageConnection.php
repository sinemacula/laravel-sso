<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Database;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;

/**
 * The connection and configured names of the package's tables, shared by the
 * models and migrations.
 *
 * Adapters that must commit with the package write through this connection;
 * the settings are fixed for a process's life.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class StorageConnection
{
    /** @var array<string, string> Every package table's setting key under `sso.`, with its default name. */
    public const array TABLES = [
        'single_use.table'             => 'sso_single_use_keys',
        'rate_limits.table'            => 'sso_rate_limits',
        'connections.table'            => 'sso_connections',
        'keys.table'                   => 'sso_keys',
        'domains.table'                => 'sso_domains',
        'enforcement.table'            => 'sso_enforcement',
        'links.table'                  => 'sso_links',
        'identity_guards.table'        => 'sso_identity_guards',
        'authorization_requests.table' => 'sso_authorization_requests',
        'handoff_codes.table'          => 'sso_handoff_codes',
    ];

    /** @var string The key, under `sso.`, of the table that lives on the counters' connection. */
    private const string RATE_LIMITS_TABLE = 'rate_limits.table';

    /** @var string A plain table name, optionally schema-qualified. */
    private const string TABLE_NAME = '/^(?:[A-Za-z_][A-Za-z0-9_]{0,62}\.)?[A-Za-z_][A-Za-z0-9_]{0,62}$/';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The storage connection, or `null` for the default connection.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public static function name(): ?string
    {
        return self::read('storage.connection', 'the default connection');
    }

    /**
     * The attempt counters' connection, or the storage connection when unset.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public static function forRateLimits(): ?string
    {
        return self::read('rate_limits.connection', 'the storage connection') ?? self::name();
    }

    /**
     * The connection the keyed table lives on.
     *
     * @param  string  $key
     * @return ?string
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function connectionFor(string $key): ?string
    {
        self::assertKnown($key);

        return $key === self::RATE_LIMITS_TABLE ? self::forRateLimits() : self::name();
    }

    /**
     * The configured name of the keyed table, or its default.
     *
     * @param  string  $key
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function table(string $key): string
    {
        self::assertKnown($key);

        return self::tableName($key, Config::get('sso.' . $key, self::TABLES[$key]));
    }

    /**
     * Whether the model lives on the storage connection, compared by name.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public static function holds(Model $model): bool
    {
        return self::nameOf($model) === self::resolvedName();
    }

    /**
     * The name of the model's connection: its own, or the default one.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function nameOf(Model $model): string
    {
        return $model->getConnectionName() ?? Config::string('database.default');
    }

    /**
     * The name of the storage connection, resolving the default.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function resolvedName(): string
    {
        return self::name() ?? Config::string('database.default');
    }

    /**
     * Throw if a transaction is open on the storage connection.
     *
     * @param  string  $message
     * @return void
     *
     * @throws \LogicException
     */
    public static function assertNoTransaction(string $message): void
    {
        if (DB::connection(self::name())->transactionLevel() > 0) {
            throw new \LogicException($message);
        }
    }

    /**
     * Throw if a transaction is open on the storage or counters' connection.
     *
     * @param  string  $message
     * @return void
     *
     * @throws \LogicException
     */
    public static function assertNoTransactionOnAny(string $message): void
    {
        self::assertNoTransaction($message);

        if (DB::connection(self::forRateLimits())->transactionLevel() > 0) {
            throw new \LogicException($message);
        }
    }

    /**
     * The configured table name, once validated.
     *
     * @param  string  $key
     * @param  mixed  $table
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function tableName(string $key, mixed $table): string
    {
        if (!is_string($table) || preg_match(self::TABLE_NAME, $table) !== 1) {
            $message = '`sso.%s` must be a table name: letters, digits and underscores, not starting with a digit, optionally after a schema and a dot.';

            throw new \InvalidArgumentException(sprintf($message, $key));
        }

        return $table;
    }

    /**
     * Refuse a key that names no package table, a programming error.
     *
     * @param  string  $key
     * @return void
     *
     * @throws \LogicException
     */
    private static function assertKnown(string $key): void
    {
        if (array_key_exists($key, self::TABLES)) {
            return;
        }

        $known = array_map(static fn (string $known): string => "`sso.{$known}`", array_keys(self::TABLES));

        throw new \LogicException(sprintf('`sso.%s` names no package table; the tables are named by %s.', $key, implode(', ', $known)));
    }

    /**
     * Read a connection name under `sso`; empty means `null`, and anything else
     * fails closed.
     *
     * @param  string  $key
     * @param  string  $fallback
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private static function read(string $key, string $fallback): ?string
    {
        $connection = Config::get('sso.' . $key);

        if ($connection !== null && !is_string($connection)) {
            throw new \InvalidArgumentException(sprintf('`sso.%s` must be a connection name, or null or empty for %s.', $key, $fallback));
        }

        return $connection === '' ? null : $connection;
    }
}
