<?php

declare(strict_types = 1);

/**
 * The messages the package can put in front of a consumer, in English
 * (SSO-12.6).
 *
 * Every line is read through `Localization\Messages` under the `sso` namespace,
 * so an application's `lang/vendor/sso/{locale}/messages.php` words them for
 * each locale, and a locale without a line gets the English here. Each line is
 * plain text, never HTML: whoever renders it escapes it. Every line is a case
 * of `Localization\Enums\Message`, and every case a line here.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

return [

    // The page that posts an AuthnRequest to the identity provider by HTTP-POST
    // (SSO-5.1, SSO-5.3)
    'post_navigation' => [
        'title'    => 'Signing you in',
        'continue' => 'Continue',
        'noscript' => 'JavaScript is turned off in your browser. Select Continue to finish signing in.',
    ],

    // The answers of a completion at the assertion consumer service or the OIDC
    // callback (SSO-5.6, SSO-5.7)
    'completion' => [
        'invalid'     => 'The sign-in response could not be accepted.',
        'redirecting' => 'Returning you to the application.',
    ],

];
