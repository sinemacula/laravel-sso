<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\Enums\LinkState;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\Domain;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Models\RateLimit;
use SineMacula\Laravel\Sso\Models\SingleUseKey;
use SineMacula\Laravel\Sso\Models\SsoModel;
use SineMacula\Laravel\Sso\Pruning\Enums\PruneKind;

/**
 * Makes one row of each kind `Pruning\Pruner` deletes, whose time is the
 * instant given, for a test of pruning to work on. A test that uses it uses
 * `UsesConnections`, `UsesDomains` and `UsesFlowTables` too, and has created
 * the tables. Each row's values are the full width of their columns, since
 * PostgreSQL pads fixed-width columns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait MakesPrunableRows
{
    /** @var int The next row's number, so each is its own. */
    private int $prunableRow = 0;

    /**
     * Make a row of the kind in the connection, its time the instant given.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \Carbon\CarbonImmutable  $at
     * @return string
     */
    protected function prunableRow(PruneKind $kind, Connection $connection, CarbonImmutable $at): string
    {
        $number = ++$this->prunableRow;

        return match ($kind) {
            PruneKind::AUTHORIZATION_REQUESTS => $this->makeAuthorizationRequest($connection, ['expires_at' => $at])->id,
            PruneKind::HANDOFF_CODES          => $this->makeHandoffCode($connection, ['expires_at' => $at])->id,
            PruneKind::SINGLE_USE_KEYS        => $this->singleUseRow($number, $at),
            PruneKind::RESERVATIONS           => $this->reservationRow($connection, $number, $at)->id,
            PruneKind::PENDING_CLAIMS         => $this->makeDomain($connection, "d{$number}.example.com", ['pending_expires_at' => $at])->id,
            PruneKind::RATE_LIMITS            => $this->counterRow($number, $at),
        };
    }

    /**
     * Make a reservation of the connection, expiring at the instant.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  int  $number
     * @param  \Carbon\CarbonImmutable  $at
     * @return \SineMacula\Laravel\Sso\Models\Link
     */
    protected function reservationRow(Connection $connection, int $number, CarbonImmutable $at): Link
    {
        return $this->makeLink($connection, "subject-{$number}", [
            'state'                  => LinkState::RESERVED,
            'provenance'             => LinkOrigin::VERIFIED_DOMAIN,
            'reservation_id'         => strtolower(str_pad(base_convert((string) $number, 10, 32), 26, '0', STR_PAD_LEFT)),
            'reservation_expires_at' => $at,
        ]);
    }

    /**
     * The primary keys of the kind's rows still stored, as strings, sorted.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @return list<string>
     */
    protected function prunableRowsLeft(PruneKind $kind): array
    {
        $model = self::prunableModel($kind);
        $keys  = array_map(static fn (mixed $key): string => (string) $key, $model->newQuery()->toBase()->pluck($model->getKeyName())->all());

        sort($keys);

        return $keys;
    }

    /**
     * An empty model of the kind.
     *
     * @param  \SineMacula\Laravel\Sso\Pruning\Enums\PruneKind  $kind
     * @return \SineMacula\Laravel\Sso\Models\SsoModel
     */
    private static function prunableModel(PruneKind $kind): SsoModel
    {
        return match ($kind) {
            PruneKind::AUTHORIZATION_REQUESTS => new AuthorizationRequest,
            PruneKind::HANDOFF_CODES          => new HandoffCode,
            PruneKind::SINGLE_USE_KEYS        => new SingleUseKey,
            PruneKind::RESERVATIONS           => new Link,
            PruneKind::PENDING_CLAIMS         => new Domain,
            PruneKind::RATE_LIMITS            => new RateLimit,
        };
    }

    /**
     * Insert a single-use key expiring at the instant.
     *
     * @param  int  $number
     * @param  \Carbon\CarbonImmutable  $at
     * @return string
     */
    private function singleUseRow(int $number, CarbonImmutable $at): string
    {
        $model = new SingleUseKey;

        $id = DB::connection($model->getConnectionName())->table($model->getTable())->insertGetId([
            'namespace'  => 'handoff_code',
            'key_digest' => hash('sha256', "key-{$number}"),
            'expires_at' => UtcDateTime::format($model, $at),
        ]);

        return (string) $id;
    }

    /**
     * Insert a counter whose window ends at the instant.
     *
     * @param  int  $number
     * @param  \Carbon\CarbonImmutable  $at
     * @return string
     */
    private function counterRow(int $number, CarbonImmutable $at): string
    {
        $model = new RateLimit;
        $key   = hash('sha256', "counter-{$number}");

        DB::connection($model->getConnectionName())->table($model->getTable())->insert([
            'key'            => $key,
            'hits'           => 1,
            'window_ends_at' => UtcDateTime::format($model, $at),
        ]);

        return $key;
    }
}
