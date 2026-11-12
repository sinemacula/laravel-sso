<?php

declare(strict_types = 1);

/*
 * The README's published `config/sso.php`.
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
