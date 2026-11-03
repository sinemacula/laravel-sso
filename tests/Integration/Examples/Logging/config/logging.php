<?php

declare(strict_types = 1);

/*
 * The logging guide's `config/logging.php` (SSO-5.7, SSO-12.5): the `sso`
 * channel the package's lines are kept apart on, a daily file under the
 * application's storage. `LoggingExampleTest` lays its channels over the
 * application's own and reads what the package wrote there. It stands in for
 * the application's own configuration file, where reading the environment
 * belongs, so the rule against `env()` outside a configuration directory is
 * ignored here.
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
