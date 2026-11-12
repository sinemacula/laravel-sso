<?php

declare(strict_types = 1);

/*
 * The published `config/sso.php` of `docs/guides/rate-limits.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

return [
    // @snippet-start rate-limits-configuration
    // config/sso.php
    'rate_limits' => [
        'authorization_request' => [
            // An office behind one NAT address starts many sign-ins a minute
            'per_ip'           => ['max' => 60, 'decay_seconds' => 60],
            'per_email_domain' => ['max' => 300, 'decay_seconds' => 60],
        ],

        'completion' => [
            'per_ip'         => ['max' => 30, 'decay_seconds' => 60],
            'per_connection' => ['max' => 600, 'decay_seconds' => 60],
        ],

        'redemption' => [
            'per_ip' => ['max' => 30, 'decay_seconds' => 60],
        ],

        'metadata' => [
            'per_connection' => ['max' => 10, 'decay_seconds' => 3600],
        ],

        'domain_check' => [
            'per_connection' => ['max' => 30, 'decay_seconds' => 3600],
        ],
    ],
    // @snippet-end rate-limits-configuration
];
