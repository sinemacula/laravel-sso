<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Keys\Enums;

/**
 * How a key operation ended: the status of a `Keys\KeyResult`.
 *
 * Stable once released: a value is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum KeyStatus: string
{
    // A key pair was added as `next`, or `current` when its use had none
    case ADDED = 'added';

    // A `next` key was made current; the key it replaced is now `retiring`
    case MADE_CURRENT = 'made_current';

    // A `next` or `retiring` key was removed
    case RETIRED = 'retired';

    // A signing certificate of the identity provider is now trusted
    case TRUSTED = 'trusted';

    // A trusted certificate was removed
    case DISTRUSTED = 'distrusted';

    // Not found, not in a state the operation moves from, or not fresh enough
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
