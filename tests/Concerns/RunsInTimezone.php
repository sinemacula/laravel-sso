<?php

declare(strict_types = 1);

namespace Tests\Concerns;

/**
 * Runs part of a test with PHP's default timezone, the one Laravel sets from
 * `app.timezone`, set to another, and restores it afterwards whatever happens.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RunsInTimezone
{
    /**
     * Run the callback with the default timezone set to the one given.
     *
     * @param  non-empty-string  $timezone
     * @param  \Closure(): void  $callback
     * @return void
     */
    protected function inTimezone(string $timezone, \Closure $callback): void
    {
        $previous = date_default_timezone_get();

        date_default_timezone_set($timezone);

        try {
            $callback();
        } finally {
            date_default_timezone_set($previous);
        }
    }
}
