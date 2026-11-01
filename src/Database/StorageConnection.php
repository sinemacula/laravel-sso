<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Database;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;

/**
 * Where the package's tables live, and what they are called: the connection the
 * shipped models read and write and the published migrations create the tables
 * on, so the models and the migrations use the same connection and table names,
 * and each table's configured name (SSO-11.10).
 *
 * Every package table lives on `sso.storage.connection` (`null` or empty for
 * the default connection). They are kept together because a completion, a
 * redemption, a connection's lifecycle change and a link's activation each
 * write several of them in one transaction, which two connections cannot commit
 * as one. An adapter that must commit with the package (a revocation, a handoff
 * consumed by the application's sign-in, a link activated with a session)
 * writes through this same Laravel connection, inside the transaction the
 * package opens: reaching the same database through another connection is not
 * atomic. The attempt counters live on `sso.rate_limits.connection` when it
 * names one, so they can stay out of a transaction a refused flow rolls back,
 * and on the storage connection otherwise.
 *
 * Every table is named by a setting under `sso.`, listed with its default in
 * `TABLES`; a table added to the package is added there, and the models (see
 * `Models\SsoModel`) and migrations read it through `table()` and
 * `connectionFor()`.
 *
 * A model takes its connection and table when it is built, so the settings must
 * stay the same for the life of a process: moving or renaming the tables is a
 * deploy, with a worker restart and a migration the application performs, not a
 * runtime switch. Connections are compared by name, a model's own or the
 * default one, so no connection is opened.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class StorageConnection
{
    /** @var array<string, string> Every package table: the key, under `sso.`, of the setting that names it, and its default name. */
    public const array TABLES = [
        'single_use.table'  => 'sso_single_use_keys',
        'rate_limits.table' => 'sso_rate_limits',
        'connections.table' => 'sso_connections',
        'keys.table'        => 'sso_keys',
        'domains.table'     => 'sso_domains',
        'enforcement.table' => 'sso_enforcement',
    ];

    /** @var string The key, under `sso.`, of the table that lives on the counters' connection. */
    private const string RATE_LIMITS_TABLE = 'rate_limits.table';

    /** @var string A table name: letters, digits and underscores, not starting with a digit, optionally after a schema named the same way. */
    private const string TABLE_NAME = '/^(?:[A-Za-z_][A-Za-z0-9_]{0,62}\.)?[A-Za-z_][A-Za-z0-9_]{0,62}$/';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The connection the package's tables live on, or `null` for the default
     * connection.
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
     * The connection the attempt counters live on: the one
     * `sso.rate_limits.connection` names, or the storage connection.
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
     * The connection the table the key names lives on: the counters' for the
     * rate limits table, and the storage connection for every other.
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
     * The configured name of the table the key names (one of `TABLES`), or its
     * default when the setting is not set. A name that is not a plain table
     * name, optionally schema-qualified, fails closed, naming the key.
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
     * Whether the model lives on the storage connection.
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
     * The name of the storage connection: the configured one, or the default
     * one.
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
     * The table name configured under the key, once it is a plain table name,
     * optionally schema-qualified.
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
     * Refuse a key that names no package table: a caller's mistake, not a
     * configuration problem.
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
     * Read a connection setting under `sso`: a name, or `null` for what an
     * empty one means. Anything else fails closed rather than falling back to
     * another connection.
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
