<?php

declare(strict_types = 1);

/*
 * The published `config/sso.php` of `docs/guides/discovery.md` (SSO-3.4,
 * SSO-12.5): the `discovery` feature on beside OIDC, and the application that
 * offers discovery with the fallback a miss leads to. `DiscoveryExampleTest`
 * lays it over the package's configuration, as Laravel lays a published file
 * over a package's, and discovers through it.
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
