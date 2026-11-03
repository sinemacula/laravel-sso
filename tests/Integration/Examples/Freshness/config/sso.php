<?php

declare(strict_types = 1);

/*
 * The published `config/sso.php` of `docs/guides/freshness.md` (SSO-2.12,
 * SSO-12.5): a trust change keeps its five minutes, a key rotation requires an
 * authentication no more than two minutes old, and every operation the file
 * does not name takes the default. `FreshnessExampleTest` lays it over the
 * package's configuration, as Laravel lays a published file over a package's,
 * and changes a connection under it.
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
