<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys\Enums;

/**
 * How a key operation ended (SSO-2.6, SSO-2.7, SSO-2.11): the status of a
 * `Keys\KeyResult`. Five name a change made, one per operation; `refused` and
 * `invalid` name a change not made, with nothing written and nothing reported.
 *
 * Backed, and stable once released: a value is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum KeyStatus: string
{
    // A key pair of the service provider's own was generated and added, as
    // `next`, or as `current` when the connection had no key of its use
    case ADDED = 'added';

    // A `next` key was made current; the key it replaced is now `retiring`
    case MADE_CURRENT = 'made_current';

    // A `next` or `retiring` key was removed
    case RETIRED = 'retired';

    // A signing certificate of the identity provider is now trusted
    case TRUSTED = 'trusted';

    // A trusted certificate was removed
    case DISTRUSTED = 'distrusted';

    // The change was refused: the connection or the key was not found, the key
    // was not in a state the operation moves it from, or the caller's
    // authentication was not fresh enough
    case REFUSED = 'refused';

    // What was given was refused; the result carries the violations
    case INVALID = 'invalid';

    /**
     * Whether the status names a change made.
     *
     * @return bool
     */
    public function isSucceeded(): bool
    {
        return $this !== self::REFUSED && $this !== self::INVALID;
    }
}
