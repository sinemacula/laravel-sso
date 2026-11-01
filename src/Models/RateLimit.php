<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Models;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;

/**
 * One attempt counter of the default attempt limiter (SSO-11.8): how many
 * attempts a key (a keyed digest of what it counts, see
 * `RateLimiting\CounterKeys`) has made in the window that ends at
 * `window_ends_at`.
 *
 * The table comes from `sso.rate_limits.table`, the connection from
 * `sso.rate_limits.connection`, or the storage connection when that names none
 * (see `Models\SsoModel`). The limiter writes the counters with single
 * statements of its own; the model exists so `model:prune` can delete counters
 * whose window has ended.
 *
 * Only the class name is public, for applications to schedule that pruning
 * with; its columns and behaviour belong to the attempt limiter.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $key
 * @property int $hits
 * @property \Carbon\CarbonImmutable $window_ends_at
 */
final class RateLimit extends SsoModel
{
    use MassPrunable;

    /** @var string The key, under `sso.`, of the setting that names the model's table. */
    protected const string TABLE = 'rate_limits.table';

    /** @var bool Indicates if the model should be timestamped. */
    public $timestamps = false;

    /** @var bool Indicates if the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var string The primary key for the model. */
    protected $primaryKey = 'key';

    /** @var string The "type" of the primary key ID. */
    protected $keyType = 'string';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = ['*'];

    /**
     * Counters whose window has ended by the package's clock, from the second
     * it names: the limiter starts a new window on the next attempt anyway, so
     * they are safe to delete.
     *
     * @return \Illuminate\Database\Eloquent\Builder<self>
     */
    public function prunable(): Builder
    {
        $now = Container::getInstance()->make(Clock::class)->now();

        return self::query()->where('window_ends_at', '<=', UtcDateTime::format($this, $now));
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
            'hits'           => 'integer',
            'window_ends_at' => UtcDateTime::class,
        ];
    }
}
