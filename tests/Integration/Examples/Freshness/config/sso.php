<?php

declare(strict_types = 1);

/*
 * The published `config/sso.php` of `docs/guides/freshness.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

return [
    // @snippet-start freshness-max-ages
    // config/sso.php
    'freshness' => [
        'max_age_seconds' => [
            'connection_trust' => 300,
            'keys_rotate'      => 120,
        ],
    ],
    // @snippet-end freshness-max-ages
];
