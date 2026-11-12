<?php

declare(strict_types = 1);

/*
 * The published `config/sso.php` of `docs/guides/outbound-requests.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

return [
    // @snippet-start outbound-refused-ranges
    'fetcher' => [
        'refused_ranges' => [
            '203.0.114.0/24',  // a partner's IPv4 network
            '198.51.101.7/32', // one of your own public IPv4 addresses
            '3fff:42::/32',    // an IPv6 range
        ],
    ],
    // @snippet-end outbound-refused-ranges
];
