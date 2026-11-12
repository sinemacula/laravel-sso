<?php

declare(strict_types = 1);

/**
 * The package's user-facing messages in English, as plain text, never HTML.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

return [

    // The page that posts an AuthnRequest to the identity provider
    'post_navigation' => [
        'title'    => 'Signing you in',
        'continue' => 'Continue',
        'noscript' => 'JavaScript is turned off in your browser. Select Continue to finish signing in.',
    ],

    // A completion at the assertion consumer service or the OIDC callback
    'completion' => [
        'invalid'     => 'The sign-in response could not be accepted.',
        'redirecting' => 'Returning you to the application.',
    ],

];
