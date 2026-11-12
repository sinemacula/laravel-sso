<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;

/**
 * A key held by the default single-use store, modelled only for `model:prune`.
 *
 * Only the class name is public API; the columns belong to the store.
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

    /** @var string The `sso.` setting that names the table. */
    protected const string TABLE = 'single_use.table';

    /** @var bool Indicates if the model should be timestamped. */
    public $timestamps = false;

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = ['*'];

    /**
     * Keys expired by the package's clock, which the store would reuse anyway.
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
