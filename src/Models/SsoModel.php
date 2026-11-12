<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Database\StorageConnection;

/**
 * Base package model, taking its table and connection from
 * `Database\StorageConnection` so it cannot disagree with its migration.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract class SsoModel extends Model
{
    /** @var string The `sso.` setting that names the table, a key of `StorageConnection::TABLES`. */
    protected const string TABLE = '';

    /**
     * Bind the configured table and connection before Eloquent reads them.
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
     * Key new rows with a lower-case ULID and stamp them from the package's
     * clock; query builder writes bypass this.
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
