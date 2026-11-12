<?php

declare(strict_types = 1);

/*
 * The protocol switches of a published `config/sso.php`; it stands in for an
 * application config file, so `env()` is allowed here.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

return [
    // qlty-ignore: phpstan:larastan.noEnvCallsOutsideOfConfig
    // @snippet-start protocol-switches
    'features' => [
        'saml2' => env('SSO_SAML2', false),
        'oidc'  => env('SSO_OIDC', false),
    ],
    // @snippet-end protocol-switches
];
