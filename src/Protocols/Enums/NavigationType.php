<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Enums;

/**
 * How the browser is sent to the identity provider (SSO-5.1): by a redirect to
 * a URL, or by a form posted to an action URL (an HTTP-POST `AuthnRequest`).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum NavigationType: string
{
    // Redirect the browser to the URL
    case REDIRECT = 'redirect';

    // Post the fields to the URL from a form the browser submits
    case POST = 'post';
}
