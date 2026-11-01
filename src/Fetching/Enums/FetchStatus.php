<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Fetching\Enums;

/**
 * How an outbound request ended (SSO-2.9). A response of any HTTP status is
 * `fetched`: whether a `400` from a token endpoint is an error is the caller's
 * to read from it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FetchStatus: string
{
    // A response was received within the caps
    case FETCHED = 'fetched';

    // The request was refused before it was sent, or a redirect was refused
    case REFUSED = 'refused';

    // The request was sent and no acceptable response came back
    case FAILED = 'failed';
}
