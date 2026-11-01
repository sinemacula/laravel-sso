<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Localization\Enums;

/**
 * A message the package can put in front of a consumer (SSO-12.6), read through
 * `Localization\Messages`.
 *
 * The value is the line's key in the package's `messages` translation file, so
 * `sso::messages.{value}` is the full key an application overrides. Every case
 * has an English line in `lang/en/messages.php`, and every line there is a
 * case. Anything else the package answers with (a failure reason, a validation
 * code) is a code the application words, not a message. Each later item adds
 * the cases it shows here, with their lines.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Message: string
{
    // The title of the page that posts an AuthnRequest to the identity provider
    // by HTTP-POST (SSO-5.1, SSO-5.3)
    case POST_NAVIGATION_TITLE = 'post_navigation.title';

    // The label of the button on that page which posts the AuthnRequest when
    // the browser does not post it itself (SSO-5.3)
    case POST_NAVIGATION_CONTINUE = 'post_navigation.continue';

    // The text on that page shown to a browser with JavaScript turned off,
    // asking the user to select the button (SSO-5.3)
    case POST_NAVIGATION_NOSCRIPT = 'post_navigation.noscript';

    // The body of the 400 a completion answers when no trusted redirect target
    // is known: an unknown connection, or a response that matches no
    // authorisation request (SSO-5.7)
    case COMPLETION_INVALID = 'completion.invalid';

    // The body of a completion's redirect to the application's redirect URI,
    // shown by a client that does not follow it (SSO-5.6, SSO-5.7)
    case COMPLETION_REDIRECTING = 'completion.redirecting';
}
