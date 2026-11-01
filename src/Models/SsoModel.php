<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;

/**
 * The base of every package model: it takes its table and its connection from
 * `Database\StorageConnection` when it is built, so a model and the migration
 * that creates its table cannot disagree on either (SSO-11.10).
 *
 * A model names the setting of its table in `TABLE`, a key of
 * `StorageConnection::TABLES` (`single_use.table`, say); the table is the
 * configured name and the connection the one that table lives on. A model that
 * names no table, or one the package does not have, fails when it is built.
 *
 * Reading security state from the write connection (SSO-11.3) is the job of the
 * query that reads it (`useWritePdo()`), not of the model.
 *
 * A model whose rows are records rather than counters or keys (connections,
 * keys and certificates) calls `identifiedAndStamped()` from its `booted()`
 * hook: each new row is given a lower-case ULID as its key, and `created_at`
 * and `updated_at` are stamped from the package's clock (SSO-11.13), in UTC
 * through `Casts\UtcDateTime`, rather than from Laravel's own timestamps.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract class SsoModel extends Model
{
    /** @var string The key, under `sso.`, of the setting that names the model's table: a key of `StorageConnection::TABLES`. */
    protected const string TABLE = '';

    /**
     * Create a model bound to its configured table and connection, read on each
     * instantiation. The table and connection have to be applied before
     * Eloquent reads them, so this is construction rather than model behaviour.
     * A malformed setting fails closed rather than reading or writing another
     * table or connection than the one meant.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    public function __construct(array $attributes = [])
    {
        $this->setTable(StorageConnection::table(static::TABLE));
        $this->setConnection(StorageConnection::connectionFor(static::TABLE));

        parent::__construct($attributes);
    }

    /**
     * Give each new row a lower-case ULID as its key, unless one is set, and
     * stamp `created_at` and `updated_at` from the package's clock as it is
     * created, and `updated_at` as it is updated. The model turns Laravel's own
     * timestamps off and casts both columns with `Casts\UtcDateTime`; a write
     * through the query builder bypasses the stamps, so the package writes
     * these models through the model.
     *
     * @return void
     */
    protected static function identifiedAndStamped(): void
    {
        static::creating(static function (Model $model): void {

            $now = Container::getInstance()->make(Clock::class)->now();

            if ($model->getKey() === null) {
                $model->setAttribute($model->getKeyName(), strtolower((string) Str::ulid()));
            }

            $model->setAttribute('created_at', $now);
            $model->setAttribute('updated_at', $now);
        });

        static::updating(static function (Model $model): void {
            $model->setAttribute('updated_at', Container::getInstance()->make(Clock::class)->now());
        });
    }
}
