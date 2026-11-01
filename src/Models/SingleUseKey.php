<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;

/**
 * One key held by the default single-use store (SSO-11.5): the digest of a key
 * recorded in its namespace, held until `expires_at`.
 *
 * The table comes from `sso.single_use.table`, the connection from the storage
 * connection (see `Models\SsoModel`). The store writes the keys with statements
 * of its own; the model exists so `model:prune` can delete keys whose expiry
 * has passed, which the store would release and record again anyway.
 *
 * Only the class name is public, for applications to schedule that pruning
 * with; its columns and behaviour belong to the single-use store.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property string $namespace
 * @property string $key_digest
 * @property \Carbon\CarbonImmutable $expires_at
 */
final class SingleUseKey extends SsoModel
{
    use MassPrunable;

    /** @var string The key, under `sso.`, of the setting that names the model's table. */
    protected const string TABLE = 'single_use.table';

    /** @var bool Indicates if the model should be timestamped. */
    public $timestamps = false;

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = ['*'];

    /**
     * Keys whose expiry has passed by the package's clock, from the second it
     * names: the store would release them and record them again anyway, so they
     * are safe to delete.
     *
     * @return \Illuminate\Database\Eloquent\Builder<self>
     */
    public function prunable(): Builder
    {
        $now = Container::getInstance()->make(Clock::class)->now();

        return self::query()->where('expires_at', '<=', UtcDateTime::format($this, $now));
    }

    /**
     * The attributes that should be cast.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'expires_at' => UtcDateTime::class,
        ];
    }
}
