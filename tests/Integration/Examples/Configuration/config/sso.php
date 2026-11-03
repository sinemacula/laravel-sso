<?php

declare(strict_types = 1);

/*
 * The configuration guide's published `config/sso.php` (SSO-5.5, SSO-12.5): the
 * applications people sign into, a web front end and a native one, every other
 * setting left to the package's own. `ConfigurationExampleTest` lays it over
 * the package's configuration, as Laravel lays a published file over a
 * package's, and signs in through each application.
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
