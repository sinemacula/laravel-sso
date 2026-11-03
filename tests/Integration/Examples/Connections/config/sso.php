<?php

declare(strict_types = 1);

/*
 * The protocol switches of a published `config/sso.php` (SSO-2.2), each read
 * from the environment and off unless it is set; every other setting is left
 * to the package's own. `ConnectionsExampleTest` lays it over the package's
 * configuration, as Laravel lays a published file over a package's, and reads
 * which protocols are available. It stands in for the application's own
 * configuration file, where reading the environment belongs, so the rule
 * against `env()` outside a configuration directory is ignored here.
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
