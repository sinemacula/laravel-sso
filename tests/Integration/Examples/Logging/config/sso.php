<?php

declare(strict_types = 1);

/*
 * The logging guide's published `config/sso.php` (SSO-5.7, SSO-9.8, SSO-11.9,
 * SSO-12.5): the channel and the diagnostic length read from the environment,
 * and the key names of the application's own adapters added to those the
 * package redacts. `LoggingExampleTest` lays it over the package's
 * configuration, as Laravel lays a published file over a package's. It stands
 * in for the application's own configuration file, where reading the
 * environment belongs, so the rule against `env()` outside a configuration
 * directory is ignored here.
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
