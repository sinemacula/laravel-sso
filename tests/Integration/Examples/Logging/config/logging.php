<?php

declare(strict_types = 1);

/*
 * The logging guide's `config/logging.php`; it stands in for an application
 * config file, so `env()` is allowed here.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

return [
    // qlty-ignore: phpstan:larastan.noEnvCallsOutsideOfConfig
    // @snippet-start logging-channel
    'channels' => [
        'sso' => [
            'driver' => 'daily',
            'path'   => storage_path('logs/sso.log'),
            'level'  => env('LOG_LEVEL', 'info'),
            'days'   => 30,
        ],
    ],
    // @snippet-end logging-channel
];
