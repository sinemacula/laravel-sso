<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Localization\Enums;

/**
 * A user-facing message; the value is its key in `sso::messages`.
 *
 * Every case has an English line in `lang/en/messages.php`, and every line
 * there is a case.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Message: string
{
    // The title of the page the client builds to post an AuthnRequest
    case POST_NAVIGATION_TITLE = 'post_navigation.title';

    // The button on that page, for a browser that does not post by itself
    case POST_NAVIGATION_CONTINUE = 'post_navigation.continue';

    // The text on that page for a browser with JavaScript off
    case POST_NAVIGATION_NOSCRIPT = 'post_navigation.noscript';

    // The body of a completion's 400 when no trusted redirect target is known
    case COMPLETION_INVALID = 'completion.invalid';

    // The body of a completion's redirect, for a client that does not follow it
    case COMPLETION_REDIRECTING = 'completion.redirecting';
}
