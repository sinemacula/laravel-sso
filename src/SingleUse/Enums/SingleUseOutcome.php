<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\SingleUse\Enums;

/**
 * How recording a key in the single-use store ended.
 *
 * A store that cannot tell throws rather than answer either.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum SingleUseOutcome: string
{
    // The key was not held in its namespace, and is now held until its expiry
    case RECORDED = 'recorded';

    // The key is already held in its namespace: a replay, refused
    case SEEN = 'seen';
}
