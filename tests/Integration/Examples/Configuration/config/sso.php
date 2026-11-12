<?php

declare(strict_types = 1);

/*
 * The configuration guide's published `config/sso.php`: a web and a native
 * application, every other setting left to the package's defaults.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

return [
    // @snippet-start configuration-applications
    'applications' => [
        'web' => [
            'redirect_uri'     => 'https://app.example.com/auth/sso/complete',
            'external_sign_in' => true,
        ],
        'mobile' => [
            'redirect_uri'        => 'com.example.app:/auth/sso/complete',
            'external_sign_in'    => true,
            'delivery'            => 'fragment',
            'discovery'           => ['enabled' => true, 'fallback_url' => 'com.example.app:/sign-in'],
            'unlinked_handoffs'   => false,
            'handoff_ttl_seconds' => 60,
        ],
    ],
    // @snippet-end configuration-applications
];
