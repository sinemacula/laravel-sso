<?php

declare(strict_types = 1);

/*
 * The logging guide's published `config/sso.php`; it stands in for an
 * application config file, so `env()` is allowed here.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

return [
    // qlty-ignore: phpstan:larastan.noEnvCallsOutsideOfConfig
    // @snippet-start logging-settings
    'logging' => [
        'channel'               => env('SSO_LOG_CHANNEL'),
        'max_diagnostic_length' => env('SSO_LOG_MAX_DIAGNOSTIC_LENGTH', 512),
        'redacted_keys'         => ['x-api-key', 'kms_token'],
    ],
    // @snippet-end logging-settings
];
