<?php

declare(strict_types = 1);

/*
 * The published `config/sso.php` of `docs/guides/discovery.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

return [
    // @snippet-start discovery-configuration
    // config/sso.php
    'features' => [
        'oidc'      => true,
        'discovery' => true,
    ],

    'applications' => [
        'web' => [
            'redirect_uri'     => 'https://app.example.com/auth/sso/complete',
            'external_sign_in' => true,
            'discovery'        => ['enabled' => true, 'fallback_url' => 'https://app.example.com/sign-in'],
        ],
    ],
    // @snippet-end discovery-configuration
];
