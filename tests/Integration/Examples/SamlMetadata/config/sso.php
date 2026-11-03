<?php

declare(strict_types = 1);

/*
 * The metadata queue of a published `config/sso.php` (SSO-2.8, SSO-11.12,
 * SSO-12.5), as `docs/guides/saml-metadata.md` shows it: where each scheduled
 * refresh is queued and how long it may run, read from the environment; every
 * other metadata setting is left as the published file holds it.
 * `SamlMetadataScheduleExampleTest` lays it over the package's configuration
 * and queues a refresh through it. It stands in for the application's own
 * configuration file, where reading the environment belongs, so the rule
 * against `env()` outside a configuration directory is ignored here.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

return [
    // qlty-ignore: phpstan:larastan.noEnvCallsOutsideOfConfig
    // @snippet-start saml-metadata-queue
    // config/sso.php
    'metadata' => [
        'queue' => [
            'connection'      => env('SSO_METADATA_QUEUE_CONNECTION'),          // null: the default queue connection
            'name'            => env('SSO_METADATA_QUEUE'),                     // null: that connection's default queue
            'timeout_seconds' => env('SSO_METADATA_QUEUE_TIMEOUT_SECONDS', 60), // 30 to 3600, at most claim_seconds
            'tries'           => env('SSO_METADATA_QUEUE_TRIES', 1),            // a failure is retried by the backoff instead
        ],
    ],
    // @snippet-end saml-metadata-queue
];
