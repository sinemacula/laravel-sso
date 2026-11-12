<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\RateLimiting;

use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Sso\Models\Casts\UtcDateTime;
use SineMacula\Laravel\Sso\Models\RateLimit;

/**
 * The attempt limiter's counter statements; every count change is one atomic
 * statement, so concurrent servers never overwrite each other.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RateLimitStore
{
    /**
     * Take a slot and return its window as stored, or, when full, the Unix time
     * to retry; a live window not ending at `$end` is kept.
     *
     * @param  string  $key
     * @param  int  $max
     * @param  int  $now
     * @param  int  $end
     * @return int|string
     */
    public function take(string $key, int $max, int $now, int $end): int|string
    {
        if ($this->writeCount($key, $max, $now, $end) || $this->storeNewCounter($key, $end) || $this->writeCount($key, $max, $now, $end)) {
            return $this->format($end);
        }

        return $this->takeFromStoredWindow($key, $max, $now);
    }

    /**
     * Give back a slot, only to the window `take()` returned it from.
     *
     * @param  string  $key
     * @param  string  $window
     * @return void
     */
    public function giveBack(string $key, string $window): void
    {
        $this->table()
            ->where('key', $key)
            ->where('window_ends_at', $window)
            ->where('hits', '>', 0)
            ->decrement('hits');
    }

    /**
     * Take from the live stored window if it has room, else return when to
     * retry, at least a second from now.
     *
     * @param  string  $key
     * @param  int  $max
     * @param  int  $now
     * @return int|string
     */
    private function takeFromStoredWindow(string $key, int $max, int $now): int|string
    {
        $counter = RateLimit::query()->useWritePdo()->whereKey($key)->first();

        if ($counter === null || $counter->window_ends_at->getTimestamp() <= $now) {
            return $now + 1;
        }

        $ends   = $counter->window_ends_at->getTimestamp();
        $window = $this->format($ends);

        if ($counter->hits < $max && $this->countIn($key, $window, $max)) {
            return $window;
        }

        return $ends;
    }

    /**
     * Count one attempt in the stored window if unchanged and with room.
     *
     * @param  string  $key
     * @param  string  $window
     * @param  int  $max
     * @return bool
     *
     * @phpstan-impure
     *
     * @imperative
     */
    private function countIn(string $key, string $window, int $max): bool
    {
        return $this->table()
            ->where('key', $key)
            ->where('window_ends_at', $window)
            ->where('hits', '<', $max)
            ->increment('hits') === 1;
    }

    /**
     * Count one attempt, restarting an ended window; the count is assigned
     * first because MySQL evaluates UPDATE assignments left to right.
     *
     * @param  string  $key
     * @param  int  $max
     * @param  int  $now
     * @param  int  $end
     * @return bool
     *
     * @phpstan-impure
     */
    private function writeCount(string $key, int $max, int $now, int $end): bool
    {
        $connection = $this->connection();
        $grammar    = $connection->getQueryGrammar();
        $table      = $grammar->wrapTable($this->model()->getTable());
        $hits       = $grammar->wrap('hits');
        $window     = $grammar->wrap('window_ends_at');
        $nowAt      = $this->format($now);
        $endAt      = $this->format($end);

        $sql = "update {$table} set {$hits} = case when {$window} <= ? then 1 else {$hits} + 1 end,"
            . " {$window} = case when {$window} <= ? then ? else {$window} end"
            . " where {$grammar->wrap('key')} = ? and ({$window} <= ? or ({$window} = ? and {$hits} < ?))";

        return $connection->update($sql, [$nowAt, $nowAt, $endAt, $key, $nowAt, $endAt, $max]) === 1;
    }

    /**
     * Create the counter with this attempt unless another request did first.
     *
     * @param  string  $key
     * @param  int  $end
     * @return bool
     *
     * @phpstan-impure
     */
    private function storeNewCounter(string $key, int $end): bool
    {
        return $this->table()->insertOrIgnore([
            'key'            => $key,
            'hits'           => 1,
            'window_ends_at' => $this->format($end),
        ]) === 1;
    }

    /**
     * A query on the counters' table.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function table(): Builder
    {
        return $this->connection()->table($this->model()->getTable());
    }

    /**
     * The counters' connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function connection(): Connection
    {
        /** @var \Illuminate\Database\Connection */
        return $this->model()->getConnection();
    }

    /**
     * A model carrying the configured table and connection.
     *
     * @return \SineMacula\Laravel\Sso\Models\RateLimit
     */
    private function model(): RateLimit
    {
        return new RateLimit;
    }

    /**
     * Format a Unix time as the connection stores times, in UTC.
     *
     * @param  int  $timestamp
     * @return string
     */
    private function format(int $timestamp): string
    {
        return UtcDateTime::format($this->model(), $timestamp);
    }
}
