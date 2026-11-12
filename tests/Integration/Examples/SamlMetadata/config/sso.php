<?php

declare(strict_types = 1);

/*
 * The metadata queue of a published `config/sso.php`. It stands in for the
 * application's own config file, so `env()` is allowed here.
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
