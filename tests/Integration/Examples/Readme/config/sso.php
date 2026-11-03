<?php

declare(strict_types = 1);

/*
 * The README's published `config/sso.php` (SSO-12.5): the application people
 * sign into, every other setting left to the package's own.
 * `ReadmeExampleTest` lays it over the package's configuration, as Laravel lays
 * a published file over a package's, and signs in through it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

return [
    // @snippet-start readme-applications
    // config/sso.php
    'applications' => [
        'web' => [
            'redirect_uri'     => 'https://app.example.com/auth/sso/complete',
            'external_sign_in' => true,
        ],
    ],
    // @snippet-end readme-applications
];
